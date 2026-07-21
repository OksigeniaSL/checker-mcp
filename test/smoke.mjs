/**
 * Smoke test: spawn the built server over stdio and exercise all three tools
 * end to end. Run after `npm run build`:  npm run smoke
 *
 * This makes REAL network calls against a stable domain (example.com), so it
 * asserts the response STRUCTURE and invariants — never exact scores, which are
 * network-dependent. It exits non-zero on any failed assertion.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const EXPECTED_CHECK_IDS = [
  "ssl", "spf", "dmarc", "dkim", "mta_sts", "mx", "dnssec", "headers", "csp",
  "web_tech", "ptr", "hsts_preload", "caa", "bimi", "blacklist", "expiry",
  "whois_redact",
];

let failures = 0;
function check(label, cond, extra) {
  if (cond) {
    console.log(`  ok   - ${label}`);
  } else {
    failures++;
    console.error(`  FAIL - ${label}${extra ? `  (${extra})` : ""}`);
  }
}

function textOf(res) {
  return res && res.content && res.content[0] ? res.content[0].text ?? "" : "";
}

const transport = new StdioClientTransport({
  command: "node",
  args: ["dist/index.js"],
});
const client = new Client({ name: "smoke-test", version: "1.0.0" });

try {
  await client.connect(transport);

  // 1) All three tools are advertised.
  const { tools } = await client.listTools();
  const names = tools.map((tt) => tt.name);
  console.log("Tools:", names.join(", "));
  for (const want of ["check_domain", "list_checks", "explain_check"]) {
    check(`tool '${want}' registered`, names.includes(want));
  }

  // 2) check_domain (json, en) against a stable real domain.
  const en = await client.callTool({
    name: "check_domain",
    arguments: { domain: "https://example.com/", format: "json", lang: "en" },
  });
  check("check_domain (en) is not an error", !en.isError, textOf(en).slice(0, 200));

  let report = null;
  try {
    report = JSON.parse(textOf(en));
  } catch (e) {
    check("check_domain (en) returns valid JSON", false, String(e));
  }
  if (report) {
    check("report has a structuredContent mirror", !!en.structuredContent);
    check("report.domain is example.com", report.domain === "example.com", report.domain);
    check("score is an integer 0..100", Number.isInteger(report.score) && report.score >= 0 && report.score <= 100, report.score);
    check("grade is a non-empty label", typeof report.grade === "string" && report.grade.length > 0, report.grade);
    check("summary has pass/warn/fail/info", report.summary && ["pass", "warn", "fail", "info"].every((k) => typeof report.summary[k] === "number"));
    const ids = (report.checks ?? []).map((c) => c.id);
    check("returns exactly the 17 expected check ids", JSON.stringify(ids) === JSON.stringify(EXPECTED_CHECK_IDS), ids.join(","));
    const total = report.summary.pass + report.summary.warn + report.summary.fail + report.summary.info;
    check("summary counts add up to checks.length", total === report.checks.length, `${total} vs ${report.checks.length}`);
    check("every check has a title and detail", report.checks.every((c) => c.title && c.detail));
  }

  // 3) es renders too (report format), and category filter works.
  const es = await client.callTool({
    name: "check_domain",
    arguments: { domain: "example.com", categories: ["email", "dns"], lang: "es" },
  });
  check("check_domain (es, filtered) is not an error", !es.isError, textOf(es).slice(0, 200));
  check("es output is non-empty text", textOf(es).length > 0);
  check("es structured output only has email+dns checks", es.structuredContent && es.structuredContent.checks.every((c) => c.category === "email" || c.category === "dns"));

  // 4) explain_check works for a known id.
  const explain = await client.callTool({
    name: "explain_check",
    arguments: { check_id: "dmarc", lang: "es" },
  });
  check("explain_check(dmarc) is not an error", !explain.isError);
  check("explain_check output mentions the id", textOf(explain).includes("dmarc"));

  // 5) list_checks lists all 17 ids.
  const list = await client.callTool({ name: "list_checks", arguments: { lang: "en" } });
  const listText = textOf(list);
  check("list_checks names every check id", EXPECTED_CHECK_IDS.every((id) => listText.includes(id)));

  // 6) Invalid input is handled as a tool error (never a crash).
  const bad = await client.callTool({
    name: "check_domain",
    arguments: { domain: "not a domain!!" },
  });
  check("invalid domain -> isError true", bad.isError === true, textOf(bad));

  // 7) Unknown check id is handled as a tool error.
  const badCheck = await client.callTool({
    name: "explain_check",
    arguments: { check_id: "does_not_exist" },
  });
  check("unknown check id -> isError true", badCheck.isError === true);
} catch (err) {
  failures++;
  console.error("Smoke test crashed:", err && err.stack ? err.stack : String(err));
} finally {
  try {
    await client.close();
  } catch {
    /* ignore */
  }
}

if (failures > 0) {
  console.error(`\nSmoke test FAILED: ${failures} assertion(s) failed.`);
  process.exit(1);
}
console.log("\nSmoke test OK.");

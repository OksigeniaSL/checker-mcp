#!/usr/bin/env node
/**
 * Oksigenia Checker MCP server.
 *
 * Exposes the domain security Checker as MCP tools over stdio, so any MCP client
 * (Claude Code, Claude Desktop, a local Ollama agent, …) can run scans
 * conversationally. The engine performs real live checks (DNS over HTTPS, HTTP,
 * RDAP, TLS) against the target domain; no telemetry, no third-party analytics.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  runChecks,
  normalizeDomain,
  isValidDomain,
  getCheckMeta,
  CATEGORIES,
  CHECK_META,
} from "./engine";
import type { Category, RawReport, Severity } from "./engine";
import { t, resolveLang, type Lang } from "./i18n";

const SEVERITY_MARK: Record<Severity, string> = {
  pass: "✓",
  warn: "⚠",
  fail: "✗",
  info: "ℹ",
};

// Type aliases (not interfaces) so they satisfy the SDK's structuredContent
// index-signature constraint.
type ResolvedCheck = {
  id: string;
  category: Category;
  severity: Severity;
  weight: number;
  title: string;
  detail: string;
  remediation?: string;
};

type ResolvedReport = {
  domain: string;
  lang: Lang;
  score: number;
  grade: string;
  summary: { pass: number; warn: number; fail: number; info: number };
  checks: ResolvedCheck[];
};

/** Turn engine keys into human text in the requested language. */
function resolveReport(raw: RawReport, lang: Lang): ResolvedReport {
  const checks = raw.checks.map<ResolvedCheck>((c) => ({
    id: c.id,
    category: c.category,
    severity: c.severity,
    weight: c.weight,
    title: t(lang, `check.${c.id}.title`),
    detail: t(lang, c.detailKey, c.params),
    // Remediation only for actionable outcomes (not pass, not non-verifiable info).
    ...(c.severity === "pass" || c.severity === "info"
      ? {}
      : { remediation: t(lang, `check.${c.id}.fix`) }),
  }));
  return {
    domain: raw.domain,
    lang,
    score: raw.score,
    grade: t(lang, raw.grade), // engine emits an i18n grade key; render it here
    summary: raw.summary,
    checks,
  };
}

function formatReport(report: ResolvedReport): string {
  const { lang } = report;
  const lines: string[] = [];
  lines.push(t(lang, "report.title", { domain: report.domain }));
  lines.push(
    t(lang, "report.score", { score: report.score, grade: report.grade }),
  );
  lines.push(t(lang, "report.summary", report.summary));

  let currentCategory: Category | null = null;
  for (const c of report.checks) {
    if (c.category !== currentCategory) {
      currentCategory = c.category;
      lines.push("");
      lines.push(`[${t(lang, `cat.${c.category}`)}]`);
    }
    lines.push(`  ${SEVERITY_MARK[c.severity]} ${c.title} — ${c.detail}`);
    if (c.remediation) {
      lines.push(`      ↳ ${t(lang, "label.fix")}: ${c.remediation}`);
    }
  }

  lines.push("");
  lines.push(t(lang, "report.note"));
  return lines.join("\n");
}

const server = new McpServer({ name: "oksigenia-checker", version: "0.1.0" });

const langSchema = z
  .enum(["es", "en"])
  .optional()
  .describe("Report language: 'es' or 'en'. Defaults to $OKSIGENIA_LANG or 'en'.");

// Structured-output schema — mirrors ResolvedReport so clients get typed results.
const checkOutputSchema = {
  domain: z.string(),
  lang: z.enum(["es", "en"]),
  score: z.number(),
  grade: z.string(),
  summary: z.object({
    pass: z.number(),
    warn: z.number(),
    fail: z.number(),
    info: z.number(),
  }),
  checks: z.array(
    z.object({
      id: z.string(),
      category: z.enum(CATEGORIES as [Category, ...Category[]]),
      severity: z.enum(["pass", "warn", "fail", "info"]),
      weight: z.number(),
      title: z.string(),
      detail: z.string(),
      remediation: z.string().optional(),
    }),
  ),
};

// --- Tool: check_domain -----------------------------------------------------

server.registerTool(
  "check_domain",
  {
    title: "Check a domain's security",
    description:
      "Run the Oksigenia Checker against a domain and return a scored security " +
      "report from real live checks (SSL/TLS, email authentication, DNS & " +
      "infrastructure, web security). Accepts a bare domain or a URL. Optionally " +
      "restrict to specific categories.",
    inputSchema: {
      domain: z
        .string()
        .min(1)
        .describe("Domain or URL to scan, e.g. 'oksigenia.com' or 'https://oksigenia.com/blog'."),
      categories: z
        .array(z.enum(CATEGORIES as [Category, ...Category[]]))
        .optional()
        .describe("Optional subset of categories. Defaults to all: " + CATEGORIES.join(", ") + "."),
      format: z
        .enum(["report", "json"])
        .optional()
        .describe("Output format: human-readable 'report' (default) or raw 'json'."),
      lang: langSchema,
    },
    outputSchema: checkOutputSchema,
  },
  async ({ domain, categories, format, lang }) => {
    const language = resolveLang(lang);
    const normalized = normalizeDomain(domain);
    if (!isValidDomain(normalized)) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: t(language, "err.invalidDomain", {
              input: domain,
              parsed: normalized,
            }),
          },
        ],
      };
    }

    try {
      const resolved = resolveReport(
        await runChecks(normalized, categories),
        language,
      );
      const text =
        format === "json"
          ? JSON.stringify(resolved, null, 2)
          : formatReport(resolved);

      return {
        content: [{ type: "text", text }],
        structuredContent: resolved,
      };
    } catch {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: t(language, "err.engineFailed", { domain: normalized }),
          },
        ],
      };
    }
  },
);

// --- Tool: list_checks ------------------------------------------------------

server.registerTool(
  "list_checks",
  {
    title: "List available checks",
    description:
      "List every check the Oksigenia Checker performs, grouped by category, with " +
      "the reason each one matters. Useful to know what check ids exist.",
    inputSchema: { lang: langSchema },
  },
  async ({ lang }) => {
    const language = resolveLang(lang);
    const lines: string[] = [];
    for (const cat of CATEGORIES) {
      lines.push(`[${t(language, `cat.${cat}`)}]  (${cat})`);
      for (const def of CHECK_META.filter((d) => d.category === cat)) {
        lines.push(`  • ${def.id} — ${t(language, `check.${def.id}.title`)}`);
        lines.push(`      ${t(language, `check.${def.id}.why`)}`);
      }
      lines.push("");
    }
    return { content: [{ type: "text", text: lines.join("\n").trimEnd() }] };
  },
);

// --- Tool: explain_check ----------------------------------------------------

server.registerTool(
  "explain_check",
  {
    title: "Explain a check and how to fix it",
    description:
      "Given a check id (see list_checks), explain what it verifies, why it matters, " +
      "and how to remediate a failure.",
    inputSchema: {
      check_id: z
        .string()
        .describe("The check id, e.g. 'ssl', 'dmarc', 'hsts_preload'."),
      lang: langSchema,
    },
  },
  async ({ check_id, lang }) => {
    const language = resolveLang(lang);
    const meta = getCheckMeta(check_id.trim());
    if (!meta) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: t(language, "err.unknownCheck", {
              id: check_id,
              list: CHECK_META.map((c) => c.id).join(", "),
            }),
          },
        ],
      };
    }
    const text = [
      `${t(language, `check.${meta.id}.title`)}  (${meta.id})`,
      `${t(language, "label.category")}: ${t(language, `cat.${meta.category}`)}`,
      `${t(language, "label.weight")}: ${meta.weight}`,
      "",
      `${t(language, "label.why")}: ${t(language, `check.${meta.id}.why`)}`,
      `${t(language, "label.fix")}: ${t(language, `check.${meta.id}.fix`)}`,
    ].join("\n");
    return { content: [{ type: "text", text }] };
  },
);

// --- Boot -------------------------------------------------------------------

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Log to stderr only — stdout is the MCP transport and must stay clean.
  console.error("oksigenia-checker MCP server running on stdio");
}

main().catch((err) => {
  console.error("Fatal error starting oksigenia-checker MCP server:", err);
  process.exit(1);
});

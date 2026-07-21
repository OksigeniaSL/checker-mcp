import { describe, it, expect } from "vitest";
import {
  runChecks,
  normalizeDomain,
  isValidDomain,
  computeScore,
  gradeKey,
  aggregate,
  answersOf,
  txtStrings,
  hasDkimKey,
  isCfIp,
  detectCfFromHttp,
  reverseIp,
  evalSpf,
  evalDmarc,
  evalDkim,
  evalMx,
  evalDnssec,
  evalCaa,
  evalMtaSts,
  evalBimi,
  evalSsl,
  evalHeaders,
  evalCsp,
  evalWebTech,
  evalPtr,
  evalHstsPreload,
  evalBlacklist,
  evalExpiry,
  evalWhoisRedact,
  countExposedWhois,
  CATEGORIES,
  CHECK_META,
  type CheckResult,
  type Severity,
  type DohResponse,
  type NetworkDeps,
} from "./engine";
import { t, LANGS, dictKeys, type Lang } from "./i18n";

// --- helpers ----------------------------------------------------------------

describe("normalizeDomain", () => {
  it("strips scheme, path, query, port and case", () => {
    expect(normalizeDomain("https://Foo.com/blog?x=1")).toBe("foo.com");
    expect(normalizeDomain("HTTP://例.example.com:8443/")).toBe("例.example.com");
    expect(normalizeDomain("user@mail.example.org")).toBe("mail.example.org");
    expect(normalizeDomain("oksigenia.com.")).toBe("oksigenia.com");
  });
});

describe("isValidDomain", () => {
  it("accepts real domains and rejects junk", () => {
    expect(isValidDomain("oksigenia.com")).toBe(true);
    expect(isValidDomain("a.b.co")).toBe(true);
    expect(isValidDomain("not a domain")).toBe(false);
    expect(isValidDomain("localhost")).toBe(false);
    expect(isValidDomain("")).toBe(false);
  });
});

// --- scoring (must match the frontend computeScore verbatim) ----------------

function mkCheck(id: string, severity: Severity): CheckResult {
  const meta = CHECK_META.find((m) => m.id === id);
  if (!meta) throw new Error(`unknown check ${id}`);
  return {
    id: meta.id,
    category: meta.category,
    severity,
    weight: meta.weight,
    detailKey: `check.${id}.x`,
  };
}

describe("computeScore / gradeKey", () => {
  it("weights sum to 100", () => {
    expect(CHECK_META.reduce((s, m) => s + m.weight, 0)).toBe(100);
  });

  it("all-pass scores 100 (grade.secure)", () => {
    const checks = CHECK_META.map((m) => mkCheck(m.id, "pass"));
    expect(computeScore(checks)).toBe(100);
    expect(aggregate(checks).grade).toBe("grade.secure");
  });

  it("all-info also scores 100 (info is non-penalising)", () => {
    const checks = CHECK_META.map((m) => mkCheck(m.id, "info"));
    expect(computeScore(checks)).toBe(100);
  });

  it("all-fail scores 0 (grade.critical)", () => {
    const checks = CHECK_META.map((m) => mkCheck(m.id, "fail"));
    expect(computeScore(checks)).toBe(0);
    expect(aggregate(checks).grade).toBe("grade.critical");
  });

  it("warn counts as floor(weight/2)", () => {
    // ssl weight 14 warn -> 7 ; csp weight 6 warn -> 3 ; everything else pass.
    const checks = CHECK_META.map((m) =>
      m.id === "ssl" || m.id === "csp" ? mkCheck(m.id, "warn") : mkCheck(m.id, "pass"),
    );
    // 100 - (14-7) - (6-3) = 100 - 7 - 3 = 90
    expect(computeScore(checks)).toBe(90);
    expect(gradeKey(90)).toBe("grade.secure");
  });

  it("a specific hand-built mix yields its exact total", () => {
    // fail ssl(14) + fail dmarc(10) + warn dkim(8->4) + warn headers(10->5),
    // rest pass. total = 100 - 14 - 10 - (8-4) - (10-5) = 100 -14 -10 -4 -5 = 67
    const failing = new Set(["ssl", "dmarc"]);
    const warning = new Set(["dkim", "headers"]);
    const checks = CHECK_META.map((m) =>
      failing.has(m.id)
        ? mkCheck(m.id, "fail")
        : warning.has(m.id)
          ? mkCheck(m.id, "warn")
          : mkCheck(m.id, "pass"),
    );
    expect(computeScore(checks)).toBe(67);
    expect(gradeKey(67)).toBe("grade.improvable");
  });

  it("a category-filtered scan is scored against its own max, not a fixed 100", () => {
    // The 6 email checks (spf10+dmarc10+dkim8+mta_sts5+mx5+bimi2 = 40) all pass.
    // An absolute sum would give 40 → grade.highrisk (the bug). Normalized: 100.
    const email = CHECK_META.filter((m) => m.category === "email").map((m) =>
      mkCheck(m.id, "pass"),
    );
    expect(email).toHaveLength(6);
    expect(computeScore(email)).toBe(100);
    expect(gradeKey(computeScore(email))).toBe("grade.secure");
  });

  it("gradeKey band boundaries", () => {
    expect(gradeKey(85)).toBe("grade.secure");
    expect(gradeKey(84)).toBe("grade.acceptable");
    expect(gradeKey(70)).toBe("grade.acceptable");
    expect(gradeKey(69)).toBe("grade.improvable");
    expect(gradeKey(50)).toBe("grade.improvable");
    expect(gradeKey(49)).toBe("grade.highrisk");
    expect(gradeKey(30)).toBe("grade.highrisk");
    expect(gradeKey(29)).toBe("grade.critical");
  });
});

// --- DoH parsing helpers ----------------------------------------------------

describe("DoH helpers", () => {
  it("answersOf filters by record type", () => {
    const resp: DohResponse = {
      Status: 0,
      Answer: [
        { type: 5, data: "cname.example.com." }, // CNAME link
        { type: 16, data: '"v=spf1 -all"' },
        { type: 16, data: '"other"' },
      ],
    };
    expect(answersOf(resp, 16)).toHaveLength(2);
    expect(answersOf(resp, 5)).toHaveLength(1);
    expect(answersOf(null, 16)).toEqual([]);
  });

  it("txtStrings strips quotes", () => {
    const resp: DohResponse = { Answer: [{ type: 16, data: '"v=spf1 include:x -all"' }] };
    expect(txtStrings(resp)).toEqual(["v=spf1 include:x -all"]);
  });

  it("hasDkimKey requires a non-empty p=", () => {
    expect(hasDkimKey('"v=DKIM1; k=rsa; p=MIGfMA0..."')).toBe(true);
    expect(hasDkimKey("v=DKIM1; p=")).toBe(false); // revoked / empty key
    expect(hasDkimKey("some unrelated txt")).toBe(false);
  });

  it("isCfIp recognises Cloudflare ranges", () => {
    expect(isCfIp("104.16.5.5")).toBe(true);
    expect(isCfIp("172.67.1.1")).toBe(true);
    expect(isCfIp("8.8.8.8")).toBe(false);
    expect(isCfIp("not-an-ip")).toBe(false);
  });

  it("detectCfFromHttp spots Cloudflare markers", () => {
    expect(detectCfFromHttp({ "cf-ray": "abc" }, "", 200)).toBe(true);
    expect(detectCfFromHttp({ server: "cloudflare" }, "", 200)).toBe(true);
    expect(detectCfFromHttp({}, "", 403)).toBe(false);
    expect(detectCfFromHttp({}, "Just a moment", 403)).toBe(true);
    expect(detectCfFromHttp({ server: "nginx" }, "hello", 200)).toBe(false);
  });

  it("reverseIp reverses octets", () => {
    expect(reverseIp("1.2.3.4")).toBe("4.3.2.1");
  });
});

// --- per-check parsers ------------------------------------------------------

describe("evalSpf", () => {
  it("covers the real branches", () => {
    expect(evalSpf([]).severity).toBe("fail"); // none
    expect(evalSpf(["v=spf1 -all", "v=spf1 ~all"]).detailKey).toBe("check.spf.multiple");
    expect(evalSpf(["v=spf1 +all"]).detailKey).toBe("check.spf.plusall");
    expect(evalSpf(["v=spf1 -all"])).toMatchObject({ severity: "pass", detailKey: "check.spf.ok" });
    expect(evalSpf(["v=spf1 ~all"])).toMatchObject({ severity: "warn", detailKey: "check.spf.soft" });
    expect(evalSpf(["v=spf1 include:a"])).toMatchObject({ severity: "warn", detailKey: "check.spf.permissive" });
  });

  it("counts DNS lookups for near/over limit", () => {
    const many = "v=spf1 " + Array.from({ length: 11 }, (_, i) => `include:h${i}.com`).join(" ") + " -all";
    expect(evalSpf([many])).toMatchObject({ severity: "fail", detailKey: "check.spf.toomany" });
    const eight = "v=spf1 " + Array.from({ length: 8 }, (_, i) => `include:h${i}.com`).join(" ") + " ~all";
    expect(evalSpf([eight])).toMatchObject({ severity: "warn", detailKey: "check.spf.near" });
  });
});

describe("evalDmarc", () => {
  it("classifies policy and issues", () => {
    expect(evalDmarc([]).detailKey).toBe("check.dmarc.none");
    expect(evalDmarc(["v=DMARC1; p=reject; rua=mailto:r@x.com; adkim=s; aspf=s"]))
      .toMatchObject({ severity: "pass", detailKey: "check.dmarc.reject" });
    expect(evalDmarc(["v=DMARC1; p=reject"]))
      .toMatchObject({ severity: "warn", detailKey: "check.dmarc.reject_warn" });
    expect(evalDmarc(["v=DMARC1; p=quarantine; rua=mailto:r@x.com"]).detailKey)
      .toBe("check.dmarc.quarantine");
    expect(evalDmarc(["v=DMARC1; p=none"]).detailKey).toBe("check.dmarc.monitor");
  });
});

describe("simple parsers", () => {
  it("evalDkim", () => {
    expect(evalDkim(["google"], ["google", "s1"])).toMatchObject({ severity: "pass" });
    expect(evalDkim([], ["google", "s1"])).toMatchObject({ severity: "fail" });
  });
  it("evalMx / evalDnssec / evalCaa presence", () => {
    expect(evalMx([{ type: 15, data: "10 mx.x." }]).severity).toBe("pass");
    expect(evalMx([]).severity).toBe("fail");
    expect(evalDnssec([{ type: 48 }]).severity).toBe("pass");
    expect(evalDnssec([]).severity).toBe("fail");
    expect(evalCaa([{ type: 257 }]).severity).toBe("pass");
    expect(evalCaa([]).severity).toBe("fail");
  });
  it("evalMtaSts", () => {
    expect(evalMtaSts(["v=STSv1; id=1"]).severity).toBe("pass");
    expect(evalMtaSts(["nope"]).severity).toBe("fail");
  });
  it("evalBimi", () => {
    expect(evalBimi([]).detailKey).toBe("check.bimi.none");
    expect(evalBimi(["v=BIMI1; l=https://x/logo.svg; a=https://x/vmc.pem"]).detailKey).toBe("check.bimi.vmc");
    expect(evalBimi(["v=BIMI1; l=https://x/logo.svg"]).detailKey).toBe("check.bimi.ok");
    expect(evalBimi(["v=BIMI1; l=http://x/logo.png"])).toMatchObject({ severity: "warn", detailKey: "check.bimi.issues" });
  });
});

describe("evalSsl", () => {
  it("maps handshake / cert states", () => {
    expect(evalSsl({ ok: false, error: "ECONNREFUSED" }).detailKey).toBe("check.ssl.refused");
    expect(evalSsl({ ok: false, error: "TIMEOUT" }).detailKey).toBe("check.ssl.unverifiable");
    expect(evalSsl({ ok: true, authorized: false, authError: "CERT_HAS_EXPIRED" }).detailKey).toBe("check.ssl.expired");
    expect(evalSsl({ ok: true, authorized: false, authError: "SELF_SIGNED_CERT_IN_CHAIN" }).detailKey).toBe("check.ssl.selfsigned");
    expect(evalSsl({ ok: true, authorized: false, authError: "ERR_TLS_CERT_ALTNAME_INVALID" }).detailKey).toBe("check.ssl.altname");
    const soon = new Date(Date.now() + 5 * 86400000).toUTCString();
    expect(evalSsl({ ok: true, authorized: true, valid_to: soon })).toMatchObject({ severity: "warn", detailKey: "check.ssl.expiring" });
    const far = new Date(Date.now() + 90 * 86400000).toUTCString();
    expect(evalSsl({ ok: true, authorized: true, valid_to: far })).toMatchObject({ severity: "pass", detailKey: "check.ssl.valid" });
  });
});

describe("evalHeaders / evalCsp / evalWebTech", () => {
  const all = {
    "strict-transport-security": "max-age=1",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  };
  it("headers count and CF/unreachable", () => {
    expect(evalHeaders(true, true, {}).detailKey).toBe("check.headers.cf");
    expect(evalHeaders(false, false, {}).detailKey).toBe("check.headers.unreachable");
    expect(evalHeaders(false, true, all)).toMatchObject({ severity: "pass", detailKey: "check.headers.ok" });
    expect(evalHeaders(false, true, { "x-frame-options": "DENY" })).toMatchObject({ severity: "fail" });
  });
  it("csp branches", () => {
    expect(evalCsp(true, true, {}).detailKey).toBe("check.csp.cf");
    expect(evalCsp(false, true, {}).detailKey).toBe("check.csp.none");
    expect(evalCsp(false, true, { "content-security-policy": "default-src 'self'" }).detailKey).toBe("check.csp.ok");
    expect(evalCsp(false, true, { "content-security-policy": "default-src 'self' 'unsafe-inline'" })).toMatchObject({ severity: "warn", detailKey: "check.csp.issues" });
  });
  it("web_tech branches", () => {
    expect(evalWebTech(false, {}, 200, '{"namespaces":["wp/v2"],"generator":"WordPress 6.5"}').detailKey).toBe("check.web_tech.wp_rest_ver");
    expect(evalWebTech(false, { "x-powered-by": "PHP/8.1" }, 404, "").detailKey).toBe("check.web_tech.exposed");
    expect(evalWebTech(true, { "x-powered-by": "PHP/8.1" }, 404, "").detailKey).toBe("check.web_tech.clean");
    expect(evalWebTech(false, { server: "nginx" }, 404, "").detailKey).toBe("check.web_tech.clean");
  });
});

describe("evalPtr / evalHstsPreload / evalBlacklist", () => {
  it("ptr branches", () => {
    expect(evalPtr(true, "104.16.1.1", [], "x.com").detailKey).toBe("check.ptr.cf");
    expect(evalPtr(false, "", [], "x.com").detailKey).toBe("check.ptr.no_a");
    expect(evalPtr(false, "5.5.5.5", [], "x.com").detailKey).toBe("check.ptr.none");
    expect(evalPtr(false, "5.5.5.5", [{ type: 12, data: "host.x.com." }], "x.com").detailKey).toBe("check.ptr.ok");
    expect(evalPtr(false, "5.5.5.5", [{ type: 12, data: "srv.fastly.net." }], "x.com").detailKey).toBe("check.ptr.cdn");
    expect(evalPtr(false, "5.5.5.5", [{ type: 12, data: "other.host." }], "x.com")).toMatchObject({ severity: "warn", detailKey: "check.ptr.mismatch" });
  });
  it("hsts preload states", () => {
    expect(evalHstsPreload(null).detailKey).toBe("check.hsts_preload.unverified");
    expect(evalHstsPreload("preloaded").severity).toBe("pass");
    expect(evalHstsPreload("pending").detailKey).toBe("check.hsts_preload.pending");
    expect(evalHstsPreload("eligible").detailKey).toBe("check.hsts_preload.eligible");
    expect(evalHstsPreload("unknown").detailKey).toBe("check.hsts_preload.absent");
  });
  it("blacklist / reputation", () => {
    expect(evalBlacklist(true, true).severity).toBe("fail");
    expect(evalBlacklist(false, true).severity).toBe("pass");
    expect(evalBlacklist(false, false).severity).toBe("info");
  });
});

describe("evalExpiry / whois", () => {
  it("expiry bands", () => {
    const mk = (days: number) => ({
      events: [{ eventAction: "expiration", eventDate: new Date(Date.now() + days * 86400000).toISOString() }],
    });
    expect(evalExpiry(null).detailKey).toBe("check.expiry.unknown");
    expect(evalExpiry(mk(120))).toMatchObject({ severity: "pass", detailKey: "check.expiry.valid" });
    expect(evalExpiry(mk(30))).toMatchObject({ severity: "warn", detailKey: "check.expiry.soon" });
    expect(evalExpiry(mk(5))).toMatchObject({ severity: "fail", detailKey: "check.expiry.urgent" });
  });
  it("counts exposed WHOIS data and classifies", () => {
    const exposed = {
      entities: [
        {
          roles: ["registrant"],
          vcardArray: ["vcard", [["fn", {}, "text", "Jane Real Person"], ["email", {}, "text", "jane@personal.com"]]],
        },
      ],
    };
    expect(countExposedWhois(exposed, "x.com")).toBe(2);
    expect(evalWhoisRedact(exposed, "x.com")).toMatchObject({ severity: "warn", detailKey: "check.whois_redact.exposed" });

    const redacted = {
      entities: [
        {
          roles: ["registrant"],
          vcardArray: ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"], ["email", {}, "text", "privacy@registrar.com"]]],
        },
      ],
    };
    expect(countExposedWhois(redacted, "x.com")).toBe(0);
    expect(evalWhoisRedact(redacted, "x.com").detailKey).toBe("check.whois_redact.protected");
    expect(evalWhoisRedact(null, "x.com").detailKey).toBe("check.whois_redact.unverified");
  });
});

// --- runChecks with fully mocked network deps (no real network) -------------

function txt(...records: string[]): DohResponse {
  return { Status: 0, Answer: records.map((r) => ({ type: 16, data: `"${r}"` })) };
}

/** A deps stub that returns "healthy" answers for oksigenia.com-like data. */
function healthyDeps(): NetworkDeps {
  return {
    doh: async (name, type) => {
      if (type === "A") return { Status: 0, Answer: [{ type: 1, data: "104.16.1.1" }] };
      if (type === "MX") return { Status: 0, Answer: [{ type: 15, data: "10 mx.x." }] };
      if (type === "DNSKEY") return { Status: 0, Answer: [{ type: 48, data: "256 3 13 ..." }] };
      if (type === "CAA") return { Status: 0, Answer: [{ type: 257, data: '0 issue "letsencrypt.org"' }] };
      if (type === "TXT" && name.startsWith("_dmarc.")) return txt("v=DMARC1; p=reject; rua=mailto:r@x.com; adkim=s; aspf=s");
      if (type === "TXT" && name.startsWith("_mta-sts.")) return txt("v=STSv1; id=1");
      if (type === "TXT" && name.startsWith("default._bimi.")) return txt("v=BIMI1; l=https://x/logo.svg; a=https://x/vmc.pem");
      if (type === "TXT" && name.includes("._domainkey.")) {
        return name.startsWith("google.") ? txt("v=DKIM1; k=rsa; p=MIGf") : { Status: 0, Answer: [] };
      }
      if (type === "TXT") return txt("v=spf1 include:_spf.x.com -all");
      return { Status: 0, Answer: [] };
    },
    dohSecurity: async () => ({ Status: 0, Answer: [{ type: 1, data: "104.16.1.1" }] }),
    httpGet: async () => ({ statusCode: 200, headers: { "cf-ray": "abc" }, body: "" }),
    rdap: async () => ({
      events: [{ eventAction: "expiration", eventDate: new Date(Date.now() + 300 * 86400000).toISOString() }],
      entities: [{ roles: ["registrant"], vcardArray: ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]] }],
    }),
    hstsPreload: async () => "preloaded",
    tls: async () => ({ ok: true, authorized: true, valid_to: new Date(Date.now() + 90 * 86400000).toUTCString(), issuer: "Let's Encrypt" }),
  };
}

describe("runChecks (mocked network)", () => {
  it("returns exactly the 17 check ids in the fixed order", async () => {
    const r = await runChecks("oksigenia.com", undefined, healthyDeps());
    expect(r.checks.map((c) => c.id)).toEqual(CHECK_META.map((m) => m.id));
  });

  it("scores a healthy domain highly and matches aggregate()", async () => {
    const r = await runChecks("oksigenia.com", undefined, healthyDeps());
    expect(r.score).toBeGreaterThanOrEqual(85);
    expect(r.grade).toBe("grade.secure");
    expect(computeScore(r.checks)).toBe(r.score);
    const total = r.summary.pass + r.summary.warn + r.summary.fail + r.summary.info;
    expect(r.checks.length).toBe(total);
  });

  it("respects the category filter", async () => {
    const r = await runChecks("oksigenia.com", ["email"], healthyDeps());
    expect(r.checks.every((c) => c.category === "email")).toBe(true);
    expect(r.checks.length).toBeGreaterThan(0);
  });

  it("never throws even when every dep rejects", async () => {
    const boom = async () => {
      throw new Error("network down");
    };
    const deps: NetworkDeps = {
      doh: boom,
      dohSecurity: boom,
      httpGet: boom,
      rdap: boom,
      hstsPreload: boom,
      tls: boom,
    };
    const r = await runChecks("example.com", undefined, deps);
    expect(r.checks.map((c) => c.id)).toEqual(CHECK_META.map((m) => m.id));
    // Degrades gracefully: no throw, valid score in range.
    expect(r.score).toBeGreaterThanOrEqual(0);
    expect(r.score).toBeLessThanOrEqual(100);
  });
});

// --- i18n -------------------------------------------------------------------

describe("i18n", () => {
  it("interpolates params and differs across languages", () => {
    expect(t("en", "report.summary", { pass: 1, warn: 2, fail: 3, info: 0 })).toContain("1 passed");
    expect(t("es", "report.summary", { pass: 1, warn: 2, fail: 3, info: 0 })).toContain("1 correctas");
  });

  it("falls back to the key when a translation is missing", () => {
    expect(t("en", "does.not.exist")).toBe("does.not.exist");
  });

  it("es and en dictionaries have exact key parity", () => {
    const en = dictKeys("en").sort();
    const es = dictKeys("es").sort();
    const onlyEn = en.filter((k) => !es.includes(k));
    const onlyEs = es.filter((k) => !en.includes(k));
    expect(onlyEn, `keys only in en: ${onlyEn.join(", ")}`).toEqual([]);
    expect(onlyEs, `keys only in es: ${onlyEs.join(", ")}`).toEqual([]);
    expect(en).toEqual(es);
  });

  it("has title/why/fix for every check in every language", () => {
    for (const lang of LANGS as Lang[]) {
      for (const { id } of CHECK_META) {
        for (const suffix of ["title", "why", "fix"]) {
          const key = `check.${id}.${suffix}`;
          expect(t(lang, key), `missing ${key} (${lang})`).not.toBe(key);
        }
      }
    }
  });

  it("resolves every grade + category key in both languages", () => {
    const keys = [
      "grade.secure", "grade.acceptable", "grade.improvable", "grade.highrisk", "grade.critical",
      ...CATEGORIES.map((c) => `cat.${c}`),
      "err.engineFailed", "err.checkFailed", "report.note", "report.title", "report.score", "report.summary",
    ];
    for (const lang of LANGS as Lang[]) {
      for (const key of keys) {
        expect(t(lang, key), `missing ${key} (${lang})`).not.toBe(key);
      }
    }
  });

  it("resolves every detailKey the parsers can emit, in every language", () => {
    // Exercise all branches by feeding sample payloads, then check both langs.
    const outcomes = [
      evalSpf([]), evalSpf(["v=spf1 -all", "v=spf1 ~all"]), evalSpf(["v=spf1 +all"]),
      evalSpf(["v=spf1 -all"]), evalSpf(["v=spf1 ~all"]), evalSpf(["v=spf1 include:a"]),
      evalSpf(["v=spf1 " + Array.from({ length: 11 }, (_, i) => `include:h${i}.com`).join(" ") + " -all"]),
      evalSpf(["v=spf1 " + Array.from({ length: 8 }, (_, i) => `include:h${i}.com`).join(" ") + " ~all"]),
      evalDmarc([]), evalDmarc(["v=DMARC1; p=reject; rua=mailto:r@x; adkim=s; aspf=s"]),
      evalDmarc(["v=DMARC1; p=reject"]), evalDmarc(["v=DMARC1; p=quarantine"]), evalDmarc(["v=DMARC1; p=none"]),
      evalDkim(["google"], ["google"]), evalDkim([], ["google"]),
      evalMx([{ type: 15 }]), evalMx([]),
      evalDnssec([{ type: 48 }]), evalDnssec([]),
      evalCaa([{ type: 257 }]), evalCaa([]),
      evalMtaSts(["v=STSv1"]), evalMtaSts([]),
      evalBimi([]), evalBimi(["v=BIMI1; l=https://x/l.svg; a=https://x/v.pem"]), evalBimi(["v=BIMI1; l=https://x/l.svg"]), evalBimi(["v=BIMI1; l=http://x/l.png"]),
      evalSsl({ ok: false, error: "ECONNREFUSED" }), evalSsl({ ok: false, error: "TIMEOUT" }),
      evalSsl({ ok: true, authorized: false, authError: "CERT_HAS_EXPIRED" }),
      evalSsl({ ok: true, authorized: false, authError: "SELF_SIGNED" }),
      evalSsl({ ok: true, authorized: false, authError: "ALTNAME" }),
      evalSsl({ ok: true, authorized: false, authError: "OTHER" }),
      evalSsl({ ok: true, authorized: true, valid_to: new Date(Date.now() + 5 * 86400000).toUTCString() }),
      evalSsl({ ok: true, authorized: true, valid_to: new Date(Date.now() + 90 * 86400000).toUTCString() }),
      evalSsl({ ok: true, authorized: true, valid_to: null }),
      evalHeaders(true, true, {}), evalHeaders(false, false, {}),
      evalHeaders(false, true, { "strict-transport-security": "1", "content-security-policy": "1", "x-frame-options": "1", "x-content-type-options": "1", "referrer-policy": "1" }),
      evalHeaders(false, true, {}),
      evalCsp(true, true, {}), evalCsp(false, false, {}), evalCsp(false, true, {}),
      evalCsp(false, true, { "content-security-policy": "default-src 'self'" }),
      evalCsp(false, true, { "content-security-policy": "'unsafe-inline'" }),
      evalWebTech(false, {}, 200, '{"namespaces":["wp/v2"],"generator":"WordPress 6.5"}'),
      evalWebTech(false, {}, 200, '{"namespaces":["wp/v2"]}'),
      evalWebTech(false, { "x-powered-by": "PHP" }, 404, ""), evalWebTech(false, {}, 404, ""),
      evalPtr(true, "1.1.1.1", [], "x.com"), evalPtr(false, "", [], "x.com"),
      evalPtr(false, "5.5.5.5", [], "x.com"), evalPtr(false, "5.5.5.5", [{ type: 12, data: "host.x.com." }], "x.com"),
      evalPtr(false, "5.5.5.5", [{ type: 12, data: "srv.fastly.net." }], "x.com"),
      evalPtr(false, "5.5.5.5", [{ type: 12, data: "other." }], "x.com"),
      evalHstsPreload(null), evalHstsPreload("preloaded"), evalHstsPreload("pending"), evalHstsPreload("eligible"), evalHstsPreload("x"),
      evalBlacklist(true, true), evalBlacklist(false, true), evalBlacklist(false, false),
      evalExpiry(null),
      evalExpiry({ events: [{ eventAction: "expiration", eventDate: new Date(Date.now() + 120 * 86400000).toISOString() }] }),
      evalExpiry({ events: [{ eventAction: "expiration", eventDate: new Date(Date.now() + 30 * 86400000).toISOString() }] }),
      evalExpiry({ events: [{ eventAction: "expiration", eventDate: new Date(Date.now() + 5 * 86400000).toISOString() }] }),
      evalWhoisRedact(null, "x.com"),
      evalWhoisRedact({ entities: [{ roles: ["registrant"], vcardArray: ["vcard", [["fn", {}, "text", "Jane"]]] }] }, "x.com"),
      evalWhoisRedact({ entities: [{ roles: ["registrant"], vcardArray: ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]] }] }, "x.com"),
    ];
    const keys = new Set(outcomes.map((o) => o.detailKey));
    keys.add("err.checkFailed");
    for (const lang of LANGS as Lang[]) {
      for (const key of keys) {
        expect(t(lang, key, { days: 1, date: "2027-01-01", count: 1, issues: 1, lookups: 9, present: 3, version: "6.5", selectors: "google", ip: "5.5.5.5", ptr: "h.x", probed: 3, id: "ssl" }), `missing ${key} (${lang})`).not.toBe(key);
      }
    }
  });
});

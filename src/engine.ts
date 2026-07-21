/**
 * Oksigenia Checker — real network engine.
 *
 * Domain security & privacy checks (SPF, DMARC, DNSSEC, TLS, HTTP headers,
 * RDAP, …) run directly over DoH + HTTP + RDAP + TLS. Every verdict comes from
 * a live lookup, not a cached or third-party score.
 *
 * DNS resolution uses Cloudflare DoH (`cloudflare-dns.com`) rather than Google,
 * for privacy, plus Cloudflare's malware/phishing resolver
 * (`security.cloudflare-dns.com`) for reputation.
 *
 * The engine stays LANGUAGE-AGNOSTIC: every result carries an i18n `detailKey`
 * (+ optional params) rather than human prose. The server renders it (i18n.ts).
 * Each check is individually resilient — on a network error/timeout it degrades
 * to an `info`/`fail` result, and `runChecks` never throws.
 */

import * as tls from "node:tls";

export type Severity = "pass" | "warn" | "fail" | "info";

export type Category = "ssl" | "email" | "dns" | "web";

export const CATEGORIES: Category[] = ["ssl", "email", "dns", "web"];

export interface CheckResult {
  id: string;
  category: Category;
  severity: Severity;
  weight: number;
  /** i18n key for the human-readable detail, e.g. "check.spf.softall". */
  detailKey: string;
  /** Interpolation params for `detailKey` (e.g. { days: 12 }). */
  params?: Record<string, string | number>;
}

export interface RawReport {
  domain: string;
  score: number; // 0..100
  grade: string; // i18n grade key, e.g. "grade.secure" (rendered by the server)
  summary: { pass: number; warn: number; fail: number; info: number };
  checks: CheckResult[];
}

/** Static metadata about a check (no evaluation logic). */
export interface CheckMeta {
  id: string;
  category: Category;
  weight: number;
}

/** A per-check verdict: severity + the i18n key that describes it. */
export interface Outcome {
  severity: Severity;
  detailKey: string;
  params?: Record<string, string | number>;
}

// --- Check catalogue --------------------------------------------------------
// Per-check weights (sum = 100). Each check contributes its weight to the score
// according to its severity (see computeScore below).
export const CHECK_META: CheckMeta[] = [
  { id: "ssl", category: "ssl", weight: 14 },
  { id: "spf", category: "email", weight: 10 },
  { id: "dmarc", category: "email", weight: 10 },
  { id: "dkim", category: "email", weight: 8 },
  { id: "mta_sts", category: "email", weight: 5 },
  { id: "mx", category: "email", weight: 5 },
  { id: "dnssec", category: "dns", weight: 7 },
  { id: "headers", category: "web", weight: 10 },
  { id: "csp", category: "web", weight: 6 },
  { id: "web_tech", category: "web", weight: 4 },
  { id: "ptr", category: "dns", weight: 3 },
  { id: "hsts_preload", category: "web", weight: 3 },
  { id: "caa", category: "dns", weight: 4 },
  { id: "bimi", category: "email", weight: 2 },
  { id: "blacklist", category: "dns", weight: 5 },
  { id: "expiry", category: "dns", weight: 2 },
  { id: "whois_redact", category: "dns", weight: 2 },
];

const META_BY_ID = new Map<string, CheckMeta>(
  CHECK_META.map((m) => [m.id, m]),
);

export function getCheckMeta(id: string): CheckMeta | undefined {
  return META_BY_ID.get(id);
}

// --- DoH / HTTP / RDAP / TLS types ------------------------------------------

export interface DohAnswer {
  name?: string;
  type?: number;
  TTL?: number;
  data?: string;
}

export interface DohResponse {
  Status?: number;
  Answer?: DohAnswer[];
}

export interface HttpResult {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

export interface TlsInfo {
  ok: boolean;
  error?: string;
  authorized?: boolean;
  authError?: string | null;
  protocol?: string | null;
  valid_to?: string | null;
  issuer?: string | null;
}

/** Injectable network primitives — real impls by default, mockable in tests. */
export interface NetworkDeps {
  doh(name: string, type: string): Promise<DohResponse>;
  dohSecurity(name: string): Promise<DohResponse>;
  httpGet(url: string): Promise<HttpResult | null>;
  rdap(domain: string): Promise<unknown | null>;
  hstsPreload(domain: string): Promise<string | null>;
  tls(domain: string): Promise<TlsInfo>;
}

// DNS record type numbers (RFC 1035 + friends).
const T_A = 1;
const T_MX = 15;
const T_TXT = 16;
const T_DNSKEY = 48;
const T_CAA = 257;

const DKIM_SELECTORS = [
  "google",
  "selector1",
  "selector2",
  "protonmail",
  "protonmail2",
  "protonmail3",
  "dkim",
  "brevo1",
  "brevo2",
  "s1",
  "s2",
  "k1",
  "k2",
  "k3",
  "mandrill",
  "zoho",
  "smtp",
  "mail",
  "default",
  "dkim1",
  "dkim2",
  "pm",
  "mailjet",
  "fm1",
  "fm2",
  "fm3",
  "hs1",
  "hs2",
  "cm",
  "titan1",
  "titan2",
  "sig1",
  "sendgrid",
];

const TIMEOUT_MS = 5000;

// --- Pure DoH helpers (unit-testable, no network) ---------------------------

/** Answer records of a given numeric type (drops CNAME chain links, etc.). */
export function answersOf(resp: DohResponse | null, type: number): DohAnswer[] {
  const ans = resp && Array.isArray(resp.Answer) ? resp.Answer : [];
  return ans.filter((a) => a.type === type);
}

/** TXT record strings with the wrapping quotes removed. */
export function txtStrings(resp: DohResponse | null): string[] {
  return answersOf(resp, T_TXT).map((a) => (a.data ?? "").replace(/"/g, ""));
}

/** A functional DKIM record carries a non-empty public key (p=<base64>). */
export function hasDkimKey(txt: string): boolean {
  return /(^|;|\s)p=[A-Za-z0-9+/]/i.test(txt.replace(/"/g, ""));
}

export function reverseIp(ip: string): string {
  return ip.split(".").reverse().join(".");
}

function isIpv4(ip: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip);
}

/** Whether an IPv4 address falls inside a published Cloudflare range. */
export function isCfIp(ip: string): boolean {
  if (!isIpv4(ip)) return false;
  const [a, b, c] = ip.split(".").map(Number);
  if (a === undefined || b === undefined || c === undefined) return false;
  return (
    (a === 104 && b >= 16 && b <= 31) ||
    (a === 172 && b >= 64 && b <= 71) ||
    (a === 162 && (b === 158 || b === 159)) ||
    (a === 141 && b === 101 && c >= 64 && c <= 127) ||
    (a === 108 && b === 162 && c >= 192) ||
    (a === 188 && b === 114 && c >= 96 && c <= 111) ||
    (a === 190 && b === 93 && c >= 240) ||
    (a === 197 && b === 234 && c >= 240) ||
    (a === 198 && b === 41 && c >= 128) ||
    (a === 131 && b === 0 && c >= 72 && c <= 75) ||
    (a === 103 && (b === 21 || b === 22 || b === 31))
  );
}

/** Detect Cloudflare from the HTTP response (headers / body / challenge). */
export function detectCfFromHttp(
  headers: Record<string, string>,
  body: string,
  statusCode: number,
): boolean {
  const server = (headers["server"] ?? "").toLowerCase();
  return !!(
    headers["cf-ray"] ||
    server.includes("cloudflare") ||
    body.includes("cf_chl") ||
    body.includes("Cloudflare") ||
    (statusCode === 403 && body.includes("Just a moment"))
  );
}

// --- Pure per-check parsers (unit-testable, no network) ---------------------

const pass = (detailKey: string, params?: Outcome["params"]): Outcome => ({
  severity: "pass",
  detailKey,
  ...(params ? { params } : {}),
});
const warn = (detailKey: string, params?: Outcome["params"]): Outcome => ({
  severity: "warn",
  detailKey,
  ...(params ? { params } : {}),
});
const fail = (detailKey: string, params?: Outcome["params"]): Outcome => ({
  severity: "fail",
  detailKey,
  ...(params ? { params } : {}),
});
const info = (detailKey: string, params?: Outcome["params"]): Outcome => ({
  severity: "info",
  detailKey,
  ...(params ? { params } : {}),
});

export function evalSpf(txts: string[]): Outcome {
  const spfAll = txts.filter((t) => t.startsWith("v=spf1"));
  const spf = spfAll[0];
  if (spfAll.length > 1) return fail("check.spf.multiple", { count: spfAll.length });
  if (!spf) return fail("check.spf.none");
  const lookups = (spf.match(/\b(include:|a[:/ ]|a$|mx[:/ ]|mx$|ptr:|exists:)/g) || [])
    .length;
  if (spf.includes("+all")) return fail("check.spf.plusall");
  if (lookups > 10) return fail("check.spf.toomany", { lookups });
  if (lookups >= 8) return warn("check.spf.near", { lookups });
  if (spf.includes("-all")) return pass("check.spf.ok", { lookups });
  if (spf.includes("~all")) return warn("check.spf.soft", { lookups });
  return warn("check.spf.permissive");
}

export function evalDmarc(txts: string[]): Outcome {
  const dmarc = txts.find((t) => t.startsWith("v=DMARC1"));
  if (!dmarc) return fail("check.dmarc.none");
  const p = (dmarc.match(/\bp=(\w+)/) || ["", ""])[1];
  const hasRua = /rua=.+/.test(dmarc);
  const pctM = dmarc.match(/\bpct=(\d+)/);
  const pct = pctM && pctM[1] ? parseInt(pctM[1], 10) : 100;
  const adkim = (dmarc.match(/\badkim=([rs])/) || ["", "r"])[1];
  const aspf = (dmarc.match(/\baspf=([rs])/) || ["", "r"])[1];
  let issues = 0;
  if (!hasRua) issues++;
  if (pct < 100) issues++;
  if (adkim === "r") issues++;
  if (aspf === "r") issues++;
  if (p === "reject" && issues === 0) return pass("check.dmarc.reject");
  if (p === "reject") return warn("check.dmarc.reject_warn", { issues });
  if (p === "quarantine") return warn("check.dmarc.quarantine", { issues });
  return warn("check.dmarc.monitor", { issues });
}

export function evalDkim(dkimFound: string[], dkimProbed: string[]): Outcome {
  if (dkimFound.length > 0)
    return pass("check.dkim.found", { selectors: dkimFound.join(", ") });
  return fail("check.dkim.none", { probed: dkimProbed.length });
}

export function evalMx(mxAnswers: DohAnswer[]): Outcome {
  return mxAnswers.length
    ? pass("check.mx.ok", { count: mxAnswers.length })
    : fail("check.mx.none");
}

// DNSKEY-presence only, not full DNSSEC chain validation — we assert the zone
// is signed, not that the chain of trust resolves. Good enough for the report;
// upgrade to chain validation if needed.
export function evalDnssec(dnskeyAnswers: DohAnswer[]): Outcome {
  return dnskeyAnswers.length ? pass("check.dnssec.pass") : fail("check.dnssec.none");
}

export function evalCaa(caaAnswers: DohAnswer[]): Outcome {
  return caaAnswers.length ? pass("check.caa.pass") : fail("check.caa.none");
}

export function evalMtaSts(txts: string[]): Outcome {
  return txts.some((t) => t.startsWith("v=STSv1"))
    ? pass("check.mta_sts.ok")
    : fail("check.mta_sts.none");
}

export function evalBimi(txts: string[]): Outcome {
  const raw = txts.find((t) => t.startsWith("v=BIMI1"));
  if (!raw) return fail("check.bimi.none");
  const url = (raw.match(/\bl=(https?:\/\/[^\s;,]+)/i) || ["", ""])[1]?.trim() ?? "";
  const vmc = (raw.match(/\ba=(https?:\/\/[^\s;,]+)/i) || ["", ""])[1]?.trim() ?? "";
  const configIssues: string[] = [];
  if (!url) configIssues.push("l");
  else if (!url.startsWith("https://")) configIssues.push("https");
  else if (!url.toLowerCase().endsWith(".svg") && !url.includes(".svg?"))
    configIssues.push("svg");
  // A missing VMC (a=) is informational, not a config error.
  if (configIssues.length === 0) {
    return vmc ? pass("check.bimi.vmc") : pass("check.bimi.ok");
  }
  return warn("check.bimi.issues", { issues: configIssues.length });
}

export function evalSsl(t: TlsInfo): Outcome {
  if (!t.ok) {
    if (t.error === "ECONNREFUSED") return fail("check.ssl.refused");
    return info("check.ssl.unverifiable");
  }
  const days = t.valid_to
    ? Math.floor((Date.parse(t.valid_to) - Date.now()) / 86400000)
    : null;
  if (!t.authorized) {
    const ae = t.authError || "";
    if (ae === "CERT_HAS_EXPIRED") return fail("check.ssl.expired");
    if (/SELF_SIGNED/.test(ae)) return fail("check.ssl.selfsigned");
    if (/ALTNAME/.test(ae)) return fail("check.ssl.altname");
    return fail("check.ssl.invalid");
  }
  if (days !== null && days < 0) return fail("check.ssl.expired");
  if (days !== null && days <= 15) return warn("check.ssl.expiring", { days });
  return days !== null
    ? pass("check.ssl.valid", { days })
    : pass("check.ssl.valid_unknown");
}

const SEC_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
];

export function evalHeaders(
  isCF: boolean,
  reachable: boolean,
  headers: Record<string, string>,
): Outcome {
  if (isCF) return pass("check.headers.cf");
  if (!reachable) return info("check.headers.unreachable");
  const present = SEC_HEADERS.filter((h) => !!headers[h]).length;
  if (present >= 5) return pass("check.headers.ok");
  if (present >= 3) return warn("check.headers.partial", { present });
  return fail("check.headers.partial", { present });
}

export function evalCsp(
  isCF: boolean,
  reachable: boolean,
  headers: Record<string, string>,
): Outcome {
  if (isCF) return pass("check.csp.cf");
  if (!reachable) return info("check.csp.unreachable");
  const csp = headers["content-security-policy"] ?? "";
  if (!csp) return fail("check.csp.none");
  let issues = 0;
  if (csp.includes("'unsafe-inline'")) issues++;
  if (csp.includes("'unsafe-eval'")) issues++;
  if (!csp.includes("default-src") && !csp.includes("script-src")) issues++;
  if (csp.includes("http:")) issues++;
  return issues === 0 ? pass("check.csp.ok") : warn("check.csp.issues", { issues });
}

export function evalWebTech(
  isCF: boolean,
  headers: Record<string, string>,
  webStatus: number | null,
  webBody: string,
): Outcome {
  if (
    webStatus === 200 &&
    (webBody.includes('"namespaces"') || webBody.includes('"wp/v2"'))
  ) {
    const vM = webBody.match(/"generator"\s*:\s*"WordPress ([0-9.]+)"/);
    if (vM && vM[1]) return warn("check.web_tech.wp_rest_ver", { version: vM[1] });
    return warn("check.web_tech.wp_rest");
  }
  if (!isCF && (headers["x-powered-by"] || headers["x-generator"]))
    return warn("check.web_tech.exposed");
  if (!isCF) {
    const sv = headers["server"] ?? "";
    if (sv && /\/[0-9]/.test(sv)) return warn("check.web_tech.exposed");
  }
  return pass("check.web_tech.clean");
}

const CDN_PTR_HINTS = [
  "cloudflare",
  "1e100.net",
  "akamai",
  "fastly",
  "amazonaws",
  "azureedge",
];

export function evalPtr(
  isCF: boolean,
  ip: string,
  ptrAnswers: DohAnswer[],
  domain: string,
): Outcome {
  if (isCF) return pass("check.ptr.cf");
  const ptrHost = (ptrAnswers[0]?.data ?? "").replace(/\.$/, "");
  if (!ip) return info("check.ptr.no_a");
  if (!ptrHost) return fail("check.ptr.none", { ip });
  const isCdnPtr = CDN_PTR_HINTS.some((c) => ptrHost.includes(c));
  const fwdMatch = ptrHost.endsWith(domain) || ptrHost.includes(domain);
  if (isCdnPtr) return pass("check.ptr.cdn", { ip });
  if (fwdMatch) return pass("check.ptr.ok", { ip });
  return warn("check.ptr.mismatch", { ip, ptr: ptrHost });
}

export function evalHstsPreload(status: string | null): Outcome {
  if (status === null) return info("check.hsts_preload.unverified");
  if (status === "preloaded") return pass("check.hsts_preload.preloaded");
  if (status === "pending") return warn("check.hsts_preload.pending");
  if (status === "eligible") return warn("check.hsts_preload.eligible");
  return warn("check.hsts_preload.absent");
}

export function evalBlacklist(repBlocked: boolean, repResolved: boolean): Outcome {
  if (repBlocked) return fail("check.blacklist.blocked");
  if (repResolved) return pass("check.blacklist.clean");
  return info("check.blacklist.unknown");
}

interface RdapLike {
  events?: Array<{ eventAction?: string; eventDate?: string }>;
  entities?: unknown[];
}

export function evalExpiry(rdap: unknown | null): Outcome {
  const r = rdap as RdapLike | null;
  if (!r || !Array.isArray(r.events)) return info("check.expiry.unknown");
  const ev = r.events.find((e) => e.eventAction === "expiration");
  if (!ev || !ev.eventDate) return info("check.expiry.unknown");
  const exp = Date.parse(ev.eventDate);
  if (isNaN(exp)) return info("check.expiry.unknown");
  const days = Math.round((exp - Date.now()) / 86400000);
  const date = new Date(exp).toISOString().split("T")[0] ?? "";
  if (days > 60) return pass("check.expiry.valid", { days, date });
  if (days > 14) return warn("check.expiry.soon", { days, date });
  return fail("check.expiry.urgent", { days, date });
}

interface VcardEntity {
  roles?: string[];
  entities?: VcardEntity[];
  vcardArray?: [string, unknown[]];
}

/** Count personal data (name/email) left un-redacted in RDAP registrant data. */
export function countExposedWhois(rdap: unknown | null, domain: string): number | null {
  const r = rdap as { entities?: VcardEntity[] } | null;
  if (!r || !Array.isArray(r.entities)) return null;
  let exposed = 0;
  const walk = (e: VcardEntity | undefined, depth: number): void => {
    if (!e || depth > 5) return;
    const roles = e.roles ?? [];
    if (!roles.some((role) => ["registrant", "tech", "admin"].includes(role))) {
      (e.entities ?? []).forEach((sub) => walk(sub, depth + 1));
      return;
    }
    const vcard = Array.isArray(e.vcardArray?.[1]) ? e.vcardArray[1] : [];
    for (const entry of vcard) {
      if (!Array.isArray(entry) || entry.length < 4) continue;
      const type = String(entry[0] ?? "");
      const val = Array.isArray(entry[3])
        ? entry[3].filter((v) => typeof v === "string").join(" ")
        : String(entry[3] ?? "");
      if (type === "fn" && val.length > 2) {
        const vl = val.toLowerCase();
        if (
          !vl.includes("redact") &&
          !vl.includes("privacy") &&
          !vl.includes("protected") &&
          !vl.includes("whoisguard") &&
          !vl.includes("withheld") &&
          val !== domain
        )
          exposed++;
      }
      if (type === "email") {
        const vl = val.toLowerCase();
        if (
          !vl.includes("privacy") &&
          !vl.includes("protect") &&
          !vl.includes("contactprivacy") &&
          !vl.includes("redacted") &&
          !vl.includes("withheld") &&
          val.includes("@")
        )
          exposed++;
      }
    }
    (e.entities ?? []).forEach((sub) => walk(sub, depth + 1));
  };
  r.entities.forEach((e) => walk(e, 0));
  return exposed;
}

export function evalWhoisRedact(rdap: unknown | null, domain: string): Outcome {
  const exposed = countExposedWhois(rdap, domain);
  if (exposed === null) return info("check.whois_redact.unverified");
  if (exposed > 0) return warn("check.whois_redact.exposed", { count: exposed });
  return pass("check.whois_redact.protected");
}

// --- Scoring ----------------------------------------------------------------
// For a FULL scan: pass/info = full weight, warn = floor(w/2), fail = 0. The 17
// weights total 100, so a full 17-check scan yields a 0..100 score directly.
// The score additionally normalizes by the weight actually present, so a
// category-filtered scan is scored against its own max instead of a fixed 100.
// For a full scan `possible === 100`, so the two paths coincide exactly.

export function computeScore(checks: CheckResult[]): number {
  let earned = 0;
  let possible = 0;
  for (const c of checks) {
    possible += c.weight;
    if (c.severity === "pass" || c.severity === "info") earned += c.weight;
    else if (c.severity === "warn") earned += Math.floor(c.weight / 2);
    // fail → +0
  }
  if (possible === 0) return 0;
  return Math.max(0, Math.min(100, Math.round((earned / possible) * 100)));
}

/** Grade band → i18n key (rendered to a label by the server). */
export function gradeKey(score: number): string {
  if (score >= 85) return "grade.secure";
  if (score >= 70) return "grade.acceptable";
  if (score >= 50) return "grade.improvable";
  if (score >= 30) return "grade.highrisk";
  return "grade.critical";
}

/** Aggregate checks into score / grade key / severity counts. */
export function aggregate(checks: CheckResult[]): {
  score: number;
  grade: string;
  summary: { pass: number; warn: number; fail: number; info: number };
} {
  const summary = { pass: 0, warn: 0, fail: 0, info: 0 };
  for (const c of checks) summary[c.severity]++;
  const score = computeScore(checks);
  return { score, grade: gradeKey(score), summary };
}

// --- Domain helpers ---------------------------------------------------------

/** Strip scheme/path/port and lowercase, so 'https://Foo.com/x' -> 'foo.com'. */
export function normalizeDomain(raw: string): string {
  let d = raw.trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, ""); // scheme
  d = d.split("/")[0] ?? d; // path
  d = (d.split("?")[0] ?? d).split("#")[0] ?? d; // query/hash
  d = d.split("@").pop() ?? d; // user@
  d = d.split(":")[0] ?? d; // port
  d = d.replace(/\.+$/, ""); // trailing dot
  return d;
}

export function isValidDomain(d: string): boolean {
  return /^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$/.test(d);
}

// --- Real network primitives ------------------------------------------------

async function fetchWithTimeout(
  url: string,
  opts: RequestInit,
  ms: number,
): Promise<Response> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ac.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function dohLookup(
  name: string,
  type: string,
  base = "https://cloudflare-dns.com/dns-query",
): Promise<DohResponse> {
  const res = await fetchWithTimeout(
    `${base}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
    { headers: { accept: "application/dns-json" } },
    TIMEOUT_MS,
  );
  return (await res.json()) as DohResponse;
}

async function httpGetImpl(url: string): Promise<HttpResult | null> {
  const res = await fetchWithTimeout(
    url,
    { redirect: "follow", headers: { "user-agent": "OksigeniaChecker/1.0" } },
    TIMEOUT_MS,
  );
  const headers: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    headers[k.toLowerCase()] = v;
  });
  let body = "";
  try {
    body = await res.text();
  } catch {
    body = "";
  }
  return { statusCode: res.status, headers, body };
}

async function rdapImpl(domain: string): Promise<unknown | null> {
  const res = await fetchWithTimeout(
    `https://rdap.org/domain/${encodeURIComponent(domain)}`,
    { redirect: "follow", headers: { accept: "application/rdap+json" } },
    TIMEOUT_MS,
  );
  if (!res.ok) return null;
  return await res.json();
}

async function hstsPreloadImpl(domain: string): Promise<string | null> {
  const res = await fetchWithTimeout(
    `https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(domain)}`,
    { headers: { accept: "application/json" } },
    TIMEOUT_MS,
  );
  if (!res.ok) return null;
  const j = (await res.json()) as { status?: unknown };
  return typeof j.status === "string" ? j.status : null;
}

function tlsImpl(domain: string): Promise<TlsInfo> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (r: TlsInfo): void => {
      if (!done) {
        done = true;
        resolve(r);
      }
    };
    try {
      const sock = tls.connect(
        {
          host: domain,
          port: 443,
          servername: domain,
          timeout: TIMEOUT_MS,
          rejectUnauthorized: false,
        },
        () => {
          const cert = sock.getPeerCertificate() || ({} as tls.PeerCertificate);
          const issuerRaw = cert.issuer ? cert.issuer.O || cert.issuer.CN : null;
          const issuer = Array.isArray(issuerRaw)
            ? issuerRaw.join(", ")
            : (issuerRaw ?? null);
          finish({
            ok: true,
            authorized: sock.authorized,
            authError: sock.authorizationError
              ? String(sock.authorizationError)
              : null,
            protocol: sock.getProtocol ? sock.getProtocol() : null,
            valid_to: cert.valid_to || null,
            issuer,
          });
          try {
            sock.end();
          } catch {
            /* ignore */
          }
        },
      );
      sock.on("error", (e: NodeJS.ErrnoException) =>
        finish({ ok: false, error: String(e.code || e.message || e) }),
      );
      sock.on("timeout", () => {
        try {
          sock.destroy();
        } catch {
          /* ignore */
        }
        finish({ ok: false, error: "TIMEOUT" });
      });
    } catch (e) {
      finish({ ok: false, error: String((e as Error).message || e) });
    }
  });
}

const defaultDeps: NetworkDeps = {
  doh: (name, type) => dohLookup(name, type),
  dohSecurity: (name) =>
    dohLookup(name, "A", "https://security.cloudflare-dns.com/dns-query"),
  httpGet: httpGetImpl,
  rdap: rdapImpl,
  hstsPreload: hstsPreloadImpl,
  tls: tlsImpl,
};

/** Resolve a promise to a fallback on rejection — keeps gathering total. */
function settle<T>(p: Promise<T>, fallback: T): Promise<T> {
  return p.then((x) => x).catch(() => fallback);
}

async function probeDkim(
  domain: string,
  deps: NetworkDeps,
): Promise<{ dkimFound: string[]; dkimProbed: string[] }> {
  const found = await Promise.all(
    DKIM_SELECTORS.map(async (sel) => {
      try {
        const r = await deps.doh(`${sel}._domainkey.${domain}`, "TXT");
        return answersOf(r, T_TXT).some((a) => hasDkimKey(a.data ?? ""))
          ? sel
          : null;
      } catch {
        return null;
      }
    }),
  );
  return {
    dkimFound: found.filter((s): s is string => s !== null),
    dkimProbed: DKIM_SELECTORS,
  };
}

// --- Public API -------------------------------------------------------------

const EMPTY_DOH: DohResponse = {};

/**
 * Run the real scan. Performs live DoH / HTTP / RDAP / TLS calls; each check is
 * individually resilient and this function never throws. `deps` is an optional
 * seam for tests — production callers pass only (domain, categories?).
 */
export async function runChecks(
  rawDomain: string,
  categories?: Category[],
  depsOverride?: Partial<NetworkDeps>,
): Promise<RawReport> {
  const domain = normalizeDomain(rawDomain);
  const active = categories && categories.length ? categories : CATEGORIES;
  const deps: NetworkDeps = { ...defaultDeps, ...depsOverride };

  try {
    // A records first (feed CF detection, PTR, and the PTR reverse lookup).
    const aResp = await settle(deps.doh(domain, "A"), EMPTY_DOH);
    const aAns = answersOf(aResp, T_A);
    const firstIp = aAns[0]?.data ?? "";

    const [
      txtApex,
      dmarcResp,
      mxResp,
      dnskeyResp,
      caaResp,
      bimiResp,
      mtaResp,
      httpResp,
      webResp,
      rdapResp,
      hstsResp,
      repResp,
      tlsResp,
      dkim,
      ptrResp,
    ] = await Promise.all([
      settle(deps.doh(domain, "TXT"), EMPTY_DOH),
      settle(deps.doh(`_dmarc.${domain}`, "TXT"), EMPTY_DOH),
      settle(deps.doh(domain, "MX"), EMPTY_DOH),
      settle(deps.doh(domain, "DNSKEY"), EMPTY_DOH),
      settle(deps.doh(domain, "CAA"), EMPTY_DOH),
      settle(deps.doh(`default._bimi.${domain}`, "TXT"), EMPTY_DOH),
      settle(deps.doh(`_mta-sts.${domain}`, "TXT"), EMPTY_DOH),
      settle(deps.httpGet(`https://${domain}`), null),
      settle(deps.httpGet(`https://${domain}/wp-json/wp/v2/`), null),
      settle(deps.rdap(domain), null),
      settle(deps.hstsPreload(domain), null),
      settle(deps.dohSecurity(domain), EMPTY_DOH),
      settle(deps.tls(domain), { ok: false, error: "not executed" } as TlsInfo),
      probeDkim(domain, deps),
      firstIp && isIpv4(firstIp)
        ? settle(deps.doh(`${reverseIp(firstIp)}.in-addr.arpa`, "PTR"), EMPTY_DOH)
        : Promise.resolve(EMPTY_DOH),
    ]);

    // Cloudflare presence: by A-record range or from the HTTP response.
    let isCF = aAns.some((a) => isCfIp(a.data ?? ""));
    let httpReachable = false;
    let headers: Record<string, string> = {};
    let statusCode: number | null = null;
    let body = "";
    if (httpResp) {
      httpReachable = true;
      headers = httpResp.headers;
      statusCode = httpResp.statusCode;
      body = httpResp.body;
      if (!isCF) isCF = detectCfFromHttp(headers, body, statusCode);
    }

    // Reputation (Cloudflare malware/phishing resolver returns 0.0.0.0 if listed).
    const repAns = answersOf(repResp, T_A);
    const repResolved = repAns.length > 0;
    const repBlocked = repAns.some((a) => a.data === "0.0.0.0");

    const webStatus = webResp ? webResp.statusCode : null;
    const webBody = webResp ? webResp.body : "";

    const outcomes: Record<string, () => Outcome> = {
      ssl: () => evalSsl(tlsResp),
      spf: () => evalSpf(txtStrings(txtApex)),
      dmarc: () => evalDmarc(txtStrings(dmarcResp)),
      dkim: () => evalDkim(dkim.dkimFound, dkim.dkimProbed),
      mta_sts: () => evalMtaSts(txtStrings(mtaResp)),
      mx: () => evalMx(answersOf(mxResp, T_MX)),
      dnssec: () => evalDnssec(answersOf(dnskeyResp, T_DNSKEY)),
      headers: () => evalHeaders(isCF, httpReachable, headers),
      csp: () => evalCsp(isCF, httpReachable, headers),
      web_tech: () => evalWebTech(isCF, headers, webStatus, webBody),
      ptr: () => evalPtr(isCF, firstIp, answersOf(ptrResp, 12), domain),
      hsts_preload: () => evalHstsPreload(hstsResp),
      caa: () => evalCaa(answersOf(caaResp, T_CAA)),
      bimi: () => evalBimi(txtStrings(bimiResp)),
      blacklist: () => evalBlacklist(repBlocked, repResolved),
      expiry: () => evalExpiry(rdapResp),
      whois_redact: () => evalWhoisRedact(rdapResp, domain),
    };

    const checks: CheckResult[] = [];
    for (const meta of CHECK_META) {
      if (!active.includes(meta.category)) continue;
      let outcome: Outcome;
      try {
        const fn = outcomes[meta.id];
        outcome = fn
          ? fn()
          : { severity: "info", detailKey: "err.checkFailed", params: { id: meta.id } };
      } catch {
        outcome = {
          severity: "info",
          detailKey: "err.checkFailed",
          params: { id: meta.id },
        };
      }
      checks.push({
        id: meta.id,
        category: meta.category,
        severity: outcome.severity,
        weight: meta.weight,
        detailKey: outcome.detailKey,
        ...(outcome.params ? { params: outcome.params } : {}),
      });
    }

    const { score, grade, summary } = aggregate(checks);
    return { domain, score, grade, summary, checks };
  } catch {
    // Catastrophic safety net: emit valid, all-info results — never throw.
    const checks: CheckResult[] = CHECK_META.filter((m) =>
      active.includes(m.category),
    ).map((m) => ({
      id: m.id,
      category: m.category,
      severity: "info" as Severity,
      weight: m.weight,
      detailKey: "err.checkFailed",
      params: { id: m.id },
    }));
    const { score, grade, summary } = aggregate(checks);
    return { domain, score, grade, summary, checks };
  }
}

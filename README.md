# @oksigenia/checker-mcp

A domain security and privacy checker exposed as an [MCP](https://modelcontextprotocol.io) server. It runs entirely on your machine, makes no telemetry calls, and resolves DNS through Cloudflare DoH instead of Google.

Ask any MCP client to scan a domain and get back a scored report covering the certificate, email authentication, DNS and infrastructure, and web security headers, with a plain remediation for anything that fails.

## Why it's different

- **Local-first.** The server runs over stdio and does its own DNS-over-HTTPS, HTTP, RDAP and TLS lookups. The only network traffic is the checks themselves.
- **Zero telemetry.** No analytics, no phone-home, no third-party scoring service in the loop.
- **Privacy by default.** DNS goes to Cloudflare DoH rather than Google, and the reputation check uses Cloudflare's malware/phishing resolver.
- **Free software.** Licensed GPL-3.0-or-later. Read it, run it, change it, self-host it.

## Tools

The server exposes three tools.

### `check_domain`

Scan a domain or URL and return a scored report from real live checks.

```jsonc
// arguments
{
  "domain": "example.com",          // bare domain or full URL
  "categories": ["ssl", "email"],   // optional subset; defaults to all
  "format": "report",               // "report" (default) or "json"
  "lang": "en"                      // "es" or "en"
}
```

### `list_checks`

List every check grouped by category, with the reason each one matters.

```jsonc
{ "lang": "en" }
```

### `explain_check`

Explain a single check by id, why it matters, and how to remediate a failure.

```jsonc
{ "check_id": "dmarc", "lang": "en" }
```

## Checks

Seventeen checks across four categories, weighted to a 0-100 score.

| Category | Check id | What it verifies |
| --- | --- | --- |
| ssl | `ssl` | SSL/TLS certificate validity and expiry |
| email | `spf` | SPF record present and not overly permissive |
| email | `dmarc` | DMARC policy and reporting |
| email | `dkim` | DKIM signing (common selectors probed) |
| email | `mta_sts` | MTA-STS against SMTP downgrade attacks |
| email | `mx` | MX records for mail delivery |
| email | `bimi` | BIMI brand logo record and VMC |
| dns | `dnssec` | DNSSEC signing on the zone |
| dns | `ptr` | PTR / forward-confirmed reverse DNS |
| dns | `caa` | CAA records restricting certificate issuance |
| dns | `blacklist` | Malware/phishing reputation |
| dns | `expiry` | Domain registration expiry |
| dns | `whois_redact` | WHOIS/RDAP personal-data redaction |
| web | `headers` | HTTP security headers (HSTS, CSP, X-Frame-Options, …) |
| web | `csp` | Content-Security-Policy quality |
| web | `web_tech` | CMS/server version and API exposure |
| web | `hsts_preload` | HSTS preload-list status |

Run `list_checks` for the full descriptions, or `explain_check` for one at a time.

## Install

Run it straight from npm with `npx`:

```bash
npx @oksigenia/checker-mcp
```

Register it with Claude Code:

```bash
claude mcp add oksigenia-checker -- npx -y @oksigenia/checker-mcp
```

Or add it to any MCP client config (works in Claude Desktop, Claude Code, or any MCP client):

```json
{
  "mcpServers": {
    "oksigenia-checker": {
      "command": "npx",
      "args": ["-y", "@oksigenia/checker-mcp"],
      "env": { "OKSIGENIA_LANG": "en" }
    }
  }
}
```

Then ask: *"Check the security of example.com"* or *"Explain the dmarc check."*

## Languages

Reports render in Spanish and English. Set the default with `OKSIGENIA_LANG` (`es` or `en`), or pass `lang` on any tool call. It defaults to English.

## Privacy

The only thing that leaves your machine is the **domain name you scan**, sent to:

- Cloudflare DoH (`cloudflare-dns.com`) and Cloudflare's security resolver, for DNS and reputation
- public RDAP (`rdap.org`), for registration and WHOIS-privacy data
- the HSTS preload API, for preload status
- the target site itself, over HTTPS, to read its certificate and security headers

There is no telemetry, no analytics, and no third-party scoring service. Nothing about your queries is stored or transmitted anywhere else.

## Develop

```bash
npm install
npm run build       # tsup -> dist/
npm run typecheck   # tsc --noEmit
npm test            # vitest (hermetic, mocked network)
npm run smoke       # spawn the built server and exercise every tool live
```

Dev watch: `npm run dev`.

- `src/engine.ts` — the network engine. Language-agnostic: returns i18n keys, not text. Every check is individually resilient and `runChecks` never throws.
- `src/i18n.ts` — es/en dictionaries and `t()`.
- `src/index.ts` — the MCP server: renders engine keys into the requested language and exposes the three tools.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the PR flow.

## License

GPL-3.0-or-later © Oksigenia SL

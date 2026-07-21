# @oksigenia/checker-mcp

All notable changes to this package are documented here. Releases and this
changelog are managed with [changesets](https://github.com/changesets/changesets)
(`npm run version`).

## 0.1.0 — Initial public release

- MCP server exposing a domain security and privacy checker over stdio, with three tools: `check_domain`, `list_checks`, and `explain_check`.
- Seventeen live checks across four categories (ssl, email, dns, web): `ssl`, `spf`, `dmarc`, `dkim`, `mta_sts`, `mx`, `bimi`, `dnssec`, `ptr`, `caa`, `blacklist`, `expiry`, `whois_redact`, `headers`, `csp`, `web_tech`, `hsts_preload`, weighted to a 0-100 score with a grade.
- Real lookups over DNS-over-HTTPS, HTTP, RDAP and TLS. DNS resolves through Cloudflare DoH for privacy.
- Local-first and zero telemetry: no analytics, no phone-home, no third-party scoring service.
- Bilingual reports (Spanish and English) with a `lang` option on every tool.

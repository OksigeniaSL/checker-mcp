# @oksigenia/checker-mcp

All notable changes to this package are documented here. Releases and this
changelog are managed with [changesets](https://github.com/changesets/changesets)
(`npm run version`).

## 0.2.0

### Minor Changes

- 99c25d8: Dependencies with known vulnerabilities updated: MCP SDK 1.32 and zod 4. Node.js 20 or later is now required (18 has reached its end of life).

### Patch Changes

- The server reports its real version to the client.
- 0aaa1e9: A domain that neither sends nor receives mail (null MX per RFC 7505, SPF `v=spf1 -all` and DMARC `p=reject`) no longer loses points for DKIM, MTA-STS and BIMI: they come out as info ("not applicable"), as on checker.oksigenia.com.

## 0.1.1

- Add the `mcpName` package field so the server can be listed on the official MCP Registry under the `com.oksigenia` namespace. No functional changes.

## 0.1.0 — Initial public release

- MCP server exposing a domain security and privacy checker over stdio, with three tools: `check_domain`, `list_checks`, and `explain_check`.
- Seventeen live checks across four categories (ssl, email, dns, web): `ssl`, `spf`, `dmarc`, `dkim`, `mta_sts`, `mx`, `bimi`, `dnssec`, `ptr`, `caa`, `blacklist`, `expiry`, `whois_redact`, `headers`, `csp`, `web_tech`, `hsts_preload`, weighted to a 0-100 score with a grade.
- Real lookups over DNS-over-HTTPS, HTTP, RDAP and TLS. DNS resolves through Cloudflare DoH for privacy.
- Local-first and zero telemetry: no analytics, no phone-home, no third-party scoring service.
- Bilingual reports (Spanish and English) with a `lang` option on every tool.

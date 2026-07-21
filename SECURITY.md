# Security Policy

## Reporting a vulnerability

Please report security issues **privately**. Do not open a public issue for a suspected vulnerability.

- Email: `dev@oksigenia.cc` (subject prefix: `[security] checker-mcp`)

We aim to acknowledge reports within a few working days and will keep you informed of the fix and the disclosure timeline. Responsible disclosure is appreciated.

## Scope notes

This server is local-first: it runs over stdio and performs no telemetry. The engine makes its own DNS-over-HTTPS, HTTP, RDAP and TLS lookups against the domain being scanned and the public resolvers listed in the README. It stores no data and holds no credentials.

---
"@oksigenia/checker-mcp": patch
---

A domain that neither sends nor receives mail (null MX per RFC 7505, SPF `v=spf1 -all` and DMARC `p=reject`) no longer loses points for DKIM, MTA-STS and BIMI: they come out as info ("not applicable"), as on checker.oksigenia.com.

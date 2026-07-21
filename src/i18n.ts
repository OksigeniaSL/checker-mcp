/**
 * Minimal i18n layer (es/en). The engine emits keys; this renders them. Add a
 * language by extending `Lang` and `DICT`.
 *
 * es and en are kept at exact key parity (see engine.test.ts).
 */

export type Lang = "es" | "en";

export const LANGS: Lang[] = ["es", "en"];

export function isLang(v: unknown): v is Lang {
  return v === "es" || v === "en";
}

/** Resolve language from an explicit input, then env, defaulting to English. */
export function resolveLang(input?: string | null): Lang {
  if (isLang(input)) return input;
  const env = process.env.OKSIGENIA_LANG;
  if (isLang(env)) return env;
  return "en";
}

/** Translate `key` in `lang`, interpolating `{name}` placeholders from params. */
export function t(
  lang: Lang,
  key: string,
  params?: Record<string, string | number>,
): string {
  const raw = DICT[lang]?.[key] ?? DICT.en[key] ?? key;
  if (!params) return raw;
  return raw.replace(/\{(\w+)\}/g, (_match, name: string) => {
    const value = params[name];
    return value === undefined ? `{${name}}` : String(value);
  });
}

const EN: Record<string, string> = {
  "report.title": "Oksigenia Checker — {domain}",
  "report.score": "Score: {score}/100  ({grade})",
  "report.summary":
    "{pass} passed · {warn} warnings · {fail} failed · {info} not verifiable",
  "report.note":
    "Live result — performed real DNS, HTTP, RDAP and TLS checks against the domain.",

  "label.fix": "Fix",
  "label.category": "Category",
  "label.weight": "Weight",
  "label.why": "Why it matters",

  "err.invalidDomain":
    "'{input}' does not look like a valid domain (parsed as '{parsed}'). Provide a domain like 'oksigenia.com'.",
  "err.unknownCheck": "Unknown check id '{id}'. Known ids: {list}.",
  "err.engineFailed":
    "The Checker could not complete the scan of '{domain}'. Please try again in a moment.",
  "err.checkFailed": "This check ('{id}') could not be evaluated.",

  "grade.secure": "SECURE",
  "grade.acceptable": "ACCEPTABLE",
  "grade.improvable": "IMPROVABLE",
  "grade.highrisk": "HIGH RISK",
  "grade.critical": "CRITICAL",

  "cat.ssl": "SSL / TLS",
  "cat.email": "Email authentication",
  "cat.dns": "DNS & infrastructure",
  "cat.web": "Web security",

  // --- SSL ---
  "check.ssl.title": "SSL/TLS certificate",
  "check.ssl.why":
    "A valid, current certificate is what makes HTTPS trustworthy; an expired or mismatched one breaks trust and can take the site offline.",
  "check.ssl.fix":
    "Install a valid certificate for the domain and automate renewal (e.g. ACME / Let's Encrypt).",
  "check.ssl.refused": "No TLS service on port 443 (connection refused).",
  "check.ssl.unverifiable":
    "The TLS handshake could not be completed; the server may be blocking automated checks.",
  "check.ssl.expired": "The certificate has expired.",
  "check.ssl.selfsigned": "The certificate is self-signed and not trusted.",
  "check.ssl.altname": "The certificate does not match this domain name.",
  "check.ssl.invalid": "The certificate is not valid.",
  "check.ssl.expiring": "The certificate expires in {days} day(s).",
  "check.ssl.valid": "Valid certificate ({days} day(s) left).",
  "check.ssl.valid_unknown": "Valid certificate.",

  // --- SPF ---
  "check.spf.title": "SPF record",
  "check.spf.why":
    "SPF declares which servers may send mail for the domain, curbing spoofing.",
  "check.spf.fix":
    "Publish a single TXT SPF record ending in '-all' once all legitimate senders are known.",
  "check.spf.multiple": "{count} SPF records found — RFC 7208 allows only one (invalid).",
  "check.spf.none": "No SPF record found.",
  "check.spf.plusall": "SPF ends in '+all' — any server may send mail as this domain.",
  "check.spf.toomany": "SPF needs {lookups} DNS lookups (limit is 10) — treated as PermError.",
  "check.spf.near": "SPF is near the DNS-lookup limit ({lookups}/10).",
  "check.spf.ok": "SPF present with '-all' ({lookups} DNS lookups, estimated).",
  "check.spf.soft": "SPF ends in '~all' (soft fail) — '-all' is stronger.",
  "check.spf.permissive": "SPF present but with a permissive policy.",

  // --- DMARC ---
  "check.dmarc.title": "DMARC policy",
  "check.dmarc.why":
    "DMARC ties SPF/DKIM together and tells receivers what to do with failures.",
  "check.dmarc.fix":
    "Publish a DMARC record with reporting (rua=) and move the policy toward p=reject.",
  "check.dmarc.none": "No DMARC record.",
  "check.dmarc.reject": "DMARC enforced with p=reject and reporting active.",
  "check.dmarc.reject_warn": "DMARC p=reject but improvable ({issues} issue(s)).",
  "check.dmarc.quarantine": "DMARC p=quarantine — raise to p=reject ({issues} issue(s)).",
  "check.dmarc.monitor": "DMARC p=none (monitoring only) — no real protection.",

  // --- DKIM ---
  "check.dkim.title": "DKIM signing",
  "check.dkim.why":
    "DKIM cryptographically signs outgoing mail so receivers can verify authenticity.",
  "check.dkim.fix":
    "Enable DKIM on the mail platform and publish the public key; if you use a custom selector, add it.",
  "check.dkim.found": "DKIM detected (selectors: {selectors}).",
  "check.dkim.none": "No DKIM selector detected ({probed} common selectors probed).",

  // --- MTA-STS ---
  "check.mta_sts.title": "MTA-STS",
  "check.mta_sts.why":
    "MTA-STS prevents downgrade attacks on mail delivery (SMTP STARTTLS).",
  "check.mta_sts.fix":
    "Publish a TXT record at _mta-sts.<domain> and serve the policy file over HTTPS.",
  "check.mta_sts.ok": "MTA-STS is active.",
  "check.mta_sts.none": "No MTA-STS record.",

  // --- MX ---
  "check.mx.title": "MX records",
  "check.mx.why":
    "MX records point to the servers that receive mail for the domain.",
  "check.mx.fix": "Publish MX records pointing to your mail provider.",
  "check.mx.ok": "{count} mail server(s) configured.",
  "check.mx.none": "No MX records.",

  // --- DNSSEC ---
  "check.dnssec.title": "DNSSEC",
  "check.dnssec.why":
    "DNSSEC signs DNS answers, protecting against cache poisoning and spoofing.",
  "check.dnssec.fix":
    "Enable DNSSEC at the DNS provider and publish the DS record at the registrar.",
  "check.dnssec.pass": "DNSSEC is enabled.",
  "check.dnssec.none": "DNSSEC is not enabled for this zone.",

  // --- Headers ---
  "check.headers.title": "HTTP security headers",
  "check.headers.why":
    "Security headers (HSTS, CSP, X-Frame-Options, …) harden the site against common browser attacks.",
  "check.headers.fix":
    "Send the missing headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.",
  "check.headers.cf": "Security headers managed by Cloudflare WAF at the edge.",
  "check.headers.unreachable": "Headers not verifiable — the server did not respond.",
  "check.headers.ok": "All five security headers present.",
  "check.headers.partial": "{present}/5 security headers present.",

  // --- CSP ---
  "check.csp.title": "Content-Security-Policy",
  "check.csp.why":
    "A CSP mitigates XSS and data-injection by restricting where resources can load from.",
  "check.csp.fix":
    "Define a Content-Security-Policy; avoid 'unsafe-inline'/'unsafe-eval' and set default-src/script-src.",
  "check.csp.cf": "CSP managed by Cloudflare WAF at the edge.",
  "check.csp.unreachable": "CSP not verifiable — the server did not respond.",
  "check.csp.none": "No Content-Security-Policy header.",
  "check.csp.ok": "Content-Security-Policy present with no obvious weaknesses.",
  "check.csp.issues": "CSP present but has {issues} weakness(es).",

  // --- Web tech ---
  "check.web_tech.title": "CMS / server exposure",
  "check.web_tech.why":
    "Exposed software versions and public APIs make it easier to target known vulnerabilities.",
  "check.web_tech.fix":
    "Hide version banners (ServerTokens Prod / server_tokens off), drop X-Powered-By, and restrict the WordPress REST API.",
  "check.web_tech.clean": "No obvious technology exposure detected.",
  "check.web_tech.wp_rest": "WordPress REST API is publicly reachable.",
  "check.web_tech.wp_rest_ver":
    "WordPress REST API public and version exposed (v{version}).",
  "check.web_tech.exposed": "Server technology exposed via response headers.",

  // --- PTR ---
  "check.ptr.title": "PTR / reverse DNS",
  "check.ptr.why":
    "A matching PTR record (FCrDNS) improves mail deliverability; missing PTR is penalised by spam filters.",
  "check.ptr.fix":
    "Set a PTR record for the server IP that matches the sending domain (dedicated mail IPs).",
  "check.ptr.cf": "Behind Cloudflare CDN — shared CDN IPs have no individual PTR (expected).",
  "check.ptr.no_a": "PTR not verified — no A record for the domain.",
  "check.ptr.none": "No PTR record for {ip}.",
  "check.ptr.cdn": "PTR points to the CDN managing the domain ({ip}).",
  "check.ptr.ok": "Forward-confirmed reverse DNS is correct ({ip}).",
  "check.ptr.mismatch": "PTR for {ip} resolves to '{ptr}', not this domain.",

  // --- HSTS preload ---
  "check.hsts_preload.title": "HSTS preload",
  "check.hsts_preload.why":
    "Preloading forces HTTPS from the very first visit in all browsers, with no exception.",
  "check.hsts_preload.fix":
    "Serve HSTS with max-age≥1 year, includeSubDomains and preload, then submit at hstspreload.org.",
  "check.hsts_preload.preloaded": "Domain is on the browser HSTS preload list.",
  "check.hsts_preload.pending": "HSTS preload submission is pending.",
  "check.hsts_preload.eligible": "Eligible for HSTS preload but not yet submitted.",
  "check.hsts_preload.absent": "Domain is not on the HSTS preload list.",
  "check.hsts_preload.unverified": "HSTS preload status could not be verified.",

  // --- CAA ---
  "check.caa.title": "CAA records",
  "check.caa.why":
    "CAA limits which certificate authorities may issue certificates for the domain.",
  "check.caa.fix": "Add a CAA record naming your authorised CA(s).",
  "check.caa.pass": "CAA records restrict certificate issuance.",
  "check.caa.none": "No CAA record — any CA may issue certificates.",

  // --- BIMI ---
  "check.bimi.title": "BIMI",
  "check.bimi.why":
    "BIMI shows your verified brand logo next to authenticated mail in supporting clients.",
  "check.bimi.fix":
    "Publish a BIMI record at default._bimi.<domain> with an HTTPS SVG logo (l=) and, for Gmail, a VMC (a=).",
  "check.bimi.vmc": "BIMI configured with a VMC.",
  "check.bimi.ok": "BIMI configured (no VMC — optional for most senders).",
  "check.bimi.none": "No BIMI record.",
  "check.bimi.issues": "BIMI record present but has {issues} configuration issue(s).",

  // --- Blacklist / reputation ---
  "check.blacklist.title": "Blocklists / reputation",
  "check.blacklist.why":
    "A domain flagged for malware or phishing is blocked by security resolvers and mail filters.",
  "check.blacklist.fix":
    "If this is your domain, it may be compromised or spoofed — investigate and request delisting.",
  "check.blacklist.blocked": "Flagged as malicious by Cloudflare's security resolver.",
  "check.blacklist.clean": "No malware/phishing flags from Cloudflare's security resolver.",
  "check.blacklist.unknown": "Reputation could not be evaluated (domain did not resolve).",

  // --- Expiry ---
  "check.expiry.title": "Domain expiry",
  "check.expiry.why":
    "An expired domain can be taken over; renewing on time protects the brand and the mail flow.",
  "check.expiry.fix": "Renew the domain and enable auto-renew at the registrar.",
  "check.expiry.valid": "Domain valid — expires {date} ({days} days).",
  "check.expiry.soon": "Domain expires in {days} days ({date}) — renew soon.",
  "check.expiry.urgent": "Domain expires in {days} days ({date}) — imminent risk.",
  "check.expiry.unknown": "Expiry date not available from RDAP.",

  // --- WHOIS redaction ---
  "check.whois_redact.title": "WHOIS privacy",
  "check.whois_redact.why":
    "Personal contact data left public in WHOIS/RDAP invites spam and social engineering.",
  "check.whois_redact.fix":
    "Enable WHOIS privacy protection at your registrar to redact personal contact data.",
  "check.whois_redact.exposed": "{count} personal data item(s) exposed in WHOIS.",
  "check.whois_redact.protected": "WHOIS contact data is protected / redacted.",
  "check.whois_redact.unverified": "WHOIS contact data could not be evaluated.",
};

const ES: Record<string, string> = {
  "report.title": "Oksigenia Checker — {domain}",
  "report.score": "Puntuación: {score}/100  ({grade})",
  "report.summary":
    "{pass} correctas · {warn} avisos · {fail} fallos · {info} no verificables",
  "report.note":
    "Resultado en vivo — se hicieron comprobaciones reales de DNS, HTTP, RDAP y TLS contra el dominio.",

  "label.fix": "Solución",
  "label.category": "Categoría",
  "label.weight": "Peso",
  "label.why": "Por qué importa",

  "err.invalidDomain":
    "'{input}' no parece un dominio válido (interpretado como '{parsed}'). Indica un dominio como 'oksigenia.com'.",
  "err.unknownCheck":
    "Id de comprobación desconocido '{id}'. Ids válidos: {list}.",
  "err.engineFailed":
    "El Checker no pudo completar el análisis de '{domain}'. Inténtalo de nuevo en unos segundos.",
  "err.checkFailed": "Esta comprobación ('{id}') no se pudo evaluar.",

  "grade.secure": "SEGURO",
  "grade.acceptable": "ACEPTABLE",
  "grade.improvable": "MEJORABLE",
  "grade.highrisk": "ALTO RIESGO",
  "grade.critical": "CRÍTICO",

  "cat.ssl": "SSL / TLS",
  "cat.email": "Autenticación de email",
  "cat.dns": "DNS e infraestructura",
  "cat.web": "Seguridad web",

  // --- SSL ---
  "check.ssl.title": "Certificado SSL/TLS",
  "check.ssl.why":
    "Un certificado válido y vigente es lo que hace fiable el HTTPS; uno caducado o que no coincide rompe la confianza y puede tumbar el sitio.",
  "check.ssl.fix":
    "Instala un certificado válido para el dominio y automatiza la renovación (p. ej. ACME / Let's Encrypt).",
  "check.ssl.refused": "Sin servicio TLS en el puerto 443 (conexión rechazada).",
  "check.ssl.unverifiable":
    "No se pudo completar el handshake TLS; el servidor puede estar bloqueando la comprobación automática.",
  "check.ssl.expired": "El certificado ha caducado.",
  "check.ssl.selfsigned": "El certificado es autofirmado y no es de confianza.",
  "check.ssl.altname": "El certificado no coincide con este dominio.",
  "check.ssl.invalid": "El certificado no es válido.",
  "check.ssl.expiring": "El certificado caduca en {days} día(s).",
  "check.ssl.valid": "Certificado válido ({days} día(s) restantes).",
  "check.ssl.valid_unknown": "Certificado válido.",

  // --- SPF ---
  "check.spf.title": "Registro SPF",
  "check.spf.why":
    "SPF declara qué servidores pueden enviar correo del dominio, frenando la suplantación.",
  "check.spf.fix":
    "Publica un único registro TXT SPF terminado en '-all' cuando conozcas todos los remitentes legítimos.",
  "check.spf.multiple": "{count} registros SPF — RFC 7208 solo permite uno (inválido).",
  "check.spf.none": "No se encontró registro SPF.",
  "check.spf.plusall": "SPF termina en '+all' — cualquier servidor puede enviar como tu dominio.",
  "check.spf.toomany": "SPF necesita {lookups} consultas DNS (límite 10) — se trata como PermError.",
  "check.spf.near": "SPF cerca del límite de consultas DNS ({lookups}/10).",
  "check.spf.ok": "SPF presente con '-all' ({lookups} consultas DNS, estimado).",
  "check.spf.soft": "SPF termina en '~all' (soft fail) — '-all' es más estricto.",
  "check.spf.permissive": "SPF presente pero con una política permisiva.",

  // --- DMARC ---
  "check.dmarc.title": "Política DMARC",
  "check.dmarc.why":
    "DMARC une SPF/DKIM e indica al receptor qué hacer ante fallos.",
  "check.dmarc.fix":
    "Publica un registro DMARC con informes (rua=) y mueve la política hacia p=reject.",
  "check.dmarc.none": "Sin registro DMARC.",
  "check.dmarc.reject": "DMARC aplicado con p=reject e informes activos.",
  "check.dmarc.reject_warn": "DMARC p=reject pero mejorable ({issues} incidencia(s)).",
  "check.dmarc.quarantine": "DMARC p=quarantine — sube a p=reject ({issues} incidencia(s)).",
  "check.dmarc.monitor": "DMARC p=none (solo monitorización) — sin protección real.",

  // --- DKIM ---
  "check.dkim.title": "Firma DKIM",
  "check.dkim.why":
    "DKIM firma criptográficamente el correo saliente para que el receptor verifique su autenticidad.",
  "check.dkim.fix":
    "Activa DKIM en la plataforma de correo y publica la clave pública; si usas un selector propio, añádelo.",
  "check.dkim.found": "DKIM detectado (selectores: {selectors}).",
  "check.dkim.none": "No se detecta selector DKIM ({probed} selectores comunes probados).",

  // --- MTA-STS ---
  "check.mta_sts.title": "MTA-STS",
  "check.mta_sts.why":
    "MTA-STS previene ataques de degradación en la entrega de correo (SMTP STARTTLS).",
  "check.mta_sts.fix":
    "Publica un registro TXT en _mta-sts.<dominio> y sirve el fichero de política por HTTPS.",
  "check.mta_sts.ok": "MTA-STS está activo.",
  "check.mta_sts.none": "Sin registro MTA-STS.",

  // --- MX ---
  "check.mx.title": "Registros MX",
  "check.mx.why":
    "Los registros MX apuntan a los servidores que reciben el correo del dominio.",
  "check.mx.fix": "Publica registros MX apuntando a tu proveedor de correo.",
  "check.mx.ok": "{count} servidor(es) de correo configurado(s).",
  "check.mx.none": "Sin registros MX.",

  // --- DNSSEC ---
  "check.dnssec.title": "DNSSEC",
  "check.dnssec.why":
    "DNSSEC firma las respuestas DNS, protegiendo frente a envenenamiento de caché y suplantación.",
  "check.dnssec.fix":
    "Activa DNSSEC en el proveedor DNS y publica el registro DS en el registrador.",
  "check.dnssec.pass": "DNSSEC está habilitado.",
  "check.dnssec.none": "DNSSEC no está habilitado en esta zona.",

  // --- Headers ---
  "check.headers.title": "Cabeceras de seguridad HTTP",
  "check.headers.why":
    "Las cabeceras de seguridad (HSTS, CSP, X-Frame-Options, …) endurecen el sitio frente a ataques comunes de navegador.",
  "check.headers.fix":
    "Envía las cabeceras que falten: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.",
  "check.headers.cf": "Cabeceras de seguridad gestionadas por Cloudflare WAF en el borde.",
  "check.headers.unreachable": "Cabeceras no verificables — el servidor no respondió.",
  "check.headers.ok": "Las cinco cabeceras de seguridad presentes.",
  "check.headers.partial": "{present}/5 cabeceras de seguridad presentes.",

  // --- CSP ---
  "check.csp.title": "Content-Security-Policy",
  "check.csp.why":
    "Una CSP mitiga XSS e inyección de datos restringiendo desde dónde se cargan recursos.",
  "check.csp.fix":
    "Define una Content-Security-Policy; evita 'unsafe-inline'/'unsafe-eval' y fija default-src/script-src.",
  "check.csp.cf": "CSP gestionada por Cloudflare WAF en el borde.",
  "check.csp.unreachable": "CSP no verificable — el servidor no respondió.",
  "check.csp.none": "Sin cabecera Content-Security-Policy.",
  "check.csp.ok": "Content-Security-Policy presente sin debilidades evidentes.",
  "check.csp.issues": "CSP presente pero con {issues} debilidad(es).",

  // --- Web tech ---
  "check.web_tech.title": "Exposición CMS / servidor",
  "check.web_tech.why":
    "Exponer versiones de software y APIs públicas facilita atacar vulnerabilidades conocidas.",
  "check.web_tech.fix":
    "Oculta las versiones (ServerTokens Prod / server_tokens off), quita X-Powered-By y restringe la REST API de WordPress.",
  "check.web_tech.clean": "No se detecta exposición tecnológica evidente.",
  "check.web_tech.wp_rest": "La REST API de WordPress es accesible públicamente.",
  "check.web_tech.wp_rest_ver":
    "REST API de WordPress pública y versión expuesta (v{version}).",
  "check.web_tech.exposed": "Tecnología del servidor expuesta en las cabeceras de respuesta.",

  // --- PTR ---
  "check.ptr.title": "PTR / DNS inverso",
  "check.ptr.why":
    "Un PTR que coincide (FCrDNS) mejora la entregabilidad del correo; la ausencia de PTR la penalizan los filtros antispam.",
  "check.ptr.fix":
    "Configura un PTR para la IP del servidor que coincida con el dominio de envío (IPs de correo dedicadas).",
  "check.ptr.cf": "Detrás de Cloudflare CDN — las IPs compartidas de CDN no tienen PTR individual (esperado).",
  "check.ptr.no_a": "PTR no verificado — sin registro A para el dominio.",
  "check.ptr.none": "Sin registro PTR para {ip}.",
  "check.ptr.cdn": "El PTR apunta al CDN que gestiona el dominio ({ip}).",
  "check.ptr.ok": "DNS inverso confirmado (FCrDNS) correcto ({ip}).",
  "check.ptr.mismatch": "El PTR de {ip} resuelve a '{ptr}', no a este dominio.",

  // --- HSTS preload ---
  "check.hsts_preload.title": "HSTS preload",
  "check.hsts_preload.why":
    "El preload fuerza HTTPS desde el primer acceso en todos los navegadores, sin excepción.",
  "check.hsts_preload.fix":
    "Sirve HSTS con max-age≥1 año, includeSubDomains y preload, y luego solicítalo en hstspreload.org.",
  "check.hsts_preload.preloaded": "El dominio está en la lista HSTS preload de los navegadores.",
  "check.hsts_preload.pending": "La solicitud de HSTS preload está pendiente.",
  "check.hsts_preload.eligible": "Elegible para HSTS preload pero aún sin solicitar.",
  "check.hsts_preload.absent": "El dominio no está en la lista HSTS preload.",
  "check.hsts_preload.unverified": "No se pudo verificar el estado de HSTS preload.",

  // --- CAA ---
  "check.caa.title": "Registros CAA",
  "check.caa.why":
    "CAA limita qué autoridades de certificación pueden emitir certificados del dominio.",
  "check.caa.fix": "Añade un registro CAA indicando tu(s) CA(s) autorizada(s).",
  "check.caa.pass": "Los registros CAA restringen la emisión de certificados.",
  "check.caa.none": "Sin registro CAA — cualquier CA puede emitir certificados.",

  // --- BIMI ---
  "check.bimi.title": "BIMI",
  "check.bimi.why":
    "BIMI muestra el logo verificado de tu marca junto al correo autenticado en los clientes compatibles.",
  "check.bimi.fix":
    "Publica un registro BIMI en default._bimi.<dominio> con un logo SVG por HTTPS (l=) y, para Gmail, un VMC (a=).",
  "check.bimi.vmc": "BIMI configurado con VMC.",
  "check.bimi.ok": "BIMI configurado (sin VMC — opcional para la mayoría de remitentes).",
  "check.bimi.none": "Sin registro BIMI.",
  "check.bimi.issues": "Registro BIMI presente pero con {issues} problema(s) de configuración.",

  // --- Blacklist / reputation ---
  "check.blacklist.title": "Listas negras / reputación",
  "check.blacklist.why":
    "Un dominio marcado por malware o phishing lo bloquean los resolvers de seguridad y los filtros de correo.",
  "check.blacklist.fix":
    "Si es tu dominio, puede estar comprometido o suplantado — investígalo y solicita la retirada.",
  "check.blacklist.blocked": "Marcado como malicioso por el resolver de seguridad de Cloudflare.",
  "check.blacklist.clean": "Sin marcas de malware/phishing en el resolver de seguridad de Cloudflare.",
  "check.blacklist.unknown": "No se pudo evaluar la reputación (el dominio no resolvió).",

  // --- Expiry ---
  "check.expiry.title": "Caducidad del dominio",
  "check.expiry.why":
    "Un dominio caducado puede ser tomado por otro; renovar a tiempo protege la marca y el correo.",
  "check.expiry.fix": "Renueva el dominio y activa la renovación automática en el registrador.",
  "check.expiry.valid": "Dominio válido — caduca el {date} ({days} días).",
  "check.expiry.soon": "El dominio caduca en {days} días ({date}) — renueva pronto.",
  "check.expiry.urgent": "El dominio caduca en {days} días ({date}) — riesgo inminente.",
  "check.expiry.unknown": "Fecha de caducidad no disponible en RDAP.",

  // --- WHOIS redaction ---
  "check.whois_redact.title": "Privacidad WHOIS",
  "check.whois_redact.why":
    "Los datos personales de contacto públicos en WHOIS/RDAP invitan al spam y la ingeniería social.",
  "check.whois_redact.fix":
    "Activa la protección de privacidad WHOIS en tu registrador para ocultar los datos de contacto personales.",
  "check.whois_redact.exposed": "{count} dato(s) personal(es) expuesto(s) en WHOIS.",
  "check.whois_redact.protected": "Los datos de contacto WHOIS están protegidos / redactados.",
  "check.whois_redact.unverified": "No se pudieron evaluar los datos de contacto WHOIS.",
};

const DICT: Record<Lang, Record<string, string>> = { en: EN, es: ES };

/** The set of translation keys defined for a language (for parity tests). */
export function dictKeys(lang: Lang): string[] {
  return Object.keys(DICT[lang]);
}

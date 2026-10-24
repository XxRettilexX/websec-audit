"""Security HTTP headers check (passive)."""
from __future__ import annotations

from websec_audit.http_client import RateLimitedClient
from websec_audit.report import Finding

CHECK_NAME = "headers"

_REQUIRED_HEADERS = {
    "Strict-Transport-Security": (
        "high",
        "HSTS assente: il browser può essere indotto (downgrade/MITM) a parlare in HTTP in chiaro "
        "anche se il sito gira su HTTPS.",
        "Imposta `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` su tutte "
        "le risposte HTTPS.",
    ),
    "Content-Security-Policy": (
        "medium",
        "CSP assente: nessuna mitigazione a livello browser contro XSS, data injection e clickjacking "
        "tramite risorse esterne non autorizzate.",
        "Definisci una Content-Security-Policy restrittiva (es. `default-src 'self'`) e allarga solo "
        "le direttive realmente necessarie.",
    ),
    "X-Content-Type-Options": (
        "low",
        "Manca `X-Content-Type-Options: nosniff`: il browser può tentare il MIME-sniffing e "
        "interpretare risposte come HTML/JS anche quando non dovrebbe.",
        "Imposta `X-Content-Type-Options: nosniff` su tutte le risposte.",
    ),
    "X-Frame-Options": (
        "medium",
        "Manca `X-Frame-Options` (e non è presente `frame-ancestors` in CSP): il sito può essere "
        "incluso in un iframe da un dominio di terzi, abilitando attacchi di clickjacking.",
        "Imposta `X-Frame-Options: DENY` (o `SAMEORIGIN`) oppure usa `Content-Security-Policy: "
        "frame-ancestors 'none'`.",
    ),
    "Referrer-Policy": (
        "info",
        "Manca `Referrer-Policy`: il browser può inviare l'URL completo (inclusi eventuali token in "
        "query string) come referrer a siti di terze parti.",
        "Imposta `Referrer-Policy: strict-origin-when-cross-origin` o più restrittiva.",
    ),
    "Permissions-Policy": (
        "info",
        "Manca `Permissions-Policy`: non vengono disabilitate esplicitamente le API del browser "
        "(camera, microfono, geolocalizzazione...) non necessarie all'applicazione.",
        "Imposta `Permissions-Policy` disabilitando le feature non usate, es. "
        "`camera=(), microphone=(), geolocation=()`.",
    ),
}


def run(url: str, client: RateLimitedClient) -> list[Finding]:
    findings: list[Finding] = []
    resp = client.get(url)
    if resp is None:
        findings.append(Finding(
            check=CHECK_NAME, title="Target non raggiungibile", severity="info",
            target=url, evidence="La richiesta GET non ha ottenuto risposta (timeout/errore di rete).",
            remediation="Verifica che l'URL sia corretto e il servizio sia online.",
        ))
        return findings

    headers = resp.headers
    is_https = url.lower().startswith("https://")

    for name, (severity, desc, remediation) in _REQUIRED_HEADERS.items():
        if name == "Strict-Transport-Security" and not is_https:
            continue
        if name not in headers:
            findings.append(Finding(
                check=CHECK_NAME, title=f"Header di sicurezza assente: {name}",
                severity=severity, target=url, evidence=desc, remediation=remediation,
                references=["https://owasp.org/www-project-secure-headers/"],
            ))

    # Deprecated / legacy header that can itself introduce issues if misconfigured.
    xxp = headers.get("X-XSS-Protection")
    if xxp and xxp.strip() not in ("0",):
        findings.append(Finding(
            check=CHECK_NAME, title="X-XSS-Protection legacy abilitato",
            severity="low", target=url,
            evidence=f"Header presente con valore {xxp!r}; è deprecato e in alcuni browser legacy "
                      f"può introdurre esso stesso vulnerabilità XSS.",
            remediation="Rimuovi l'header o impostalo a `X-XSS-Protection: 0` e affidati a una CSP "
                        "solida invece del filtro XSS legacy del browser.",
        ))

    server = headers.get("Server")
    if server and any(ch.isdigit() for ch in server):
        findings.append(Finding(
            check=CHECK_NAME, title="Versione software esposta nell'header Server",
            severity="low", target=url,
            evidence=f"Header `Server: {server}` rivela nome e versione del software.",
            remediation="Configura il webserver/proxy per non includere la versione nell'header "
                        "`Server` (es. `server_tokens off;` su nginx).",
        ))

    powered_by = headers.get("X-Powered-By")
    if powered_by:
        findings.append(Finding(
            check=CHECK_NAME, title="Header X-Powered-By esposto",
            severity="info", target=url,
            evidence=f"`X-Powered-By: {powered_by}` rivela lo stack applicativo usato, utile a un "
                      f"attaccante per selezionare exploit noti.",
            remediation="Disabilita l'header `X-Powered-By` nel framework/server (es. "
                        "`app.disable('x-powered-by')` in Express).",
        ))

    return findings

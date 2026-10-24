"""Cookie security attributes check (passive)."""
from __future__ import annotations

from http.cookies import SimpleCookie

from websec_audit.http_client import RateLimitedClient
from websec_audit.report import Finding

CHECK_NAME = "cookies"


def run(url: str, client: RateLimitedClient) -> list[Finding]:
    findings: list[Finding] = []
    resp = client.get(url)
    if resp is None:
        return findings

    raw_cookies = resp.raw.headers.get_all("Set-Cookie") if resp.raw and hasattr(resp.raw.headers, "get_all") else None
    if not raw_cookies:
        set_cookie = resp.headers.get("Set-Cookie")
        raw_cookies = [set_cookie] if set_cookie else []

    is_https = url.lower().startswith("https://")

    for raw in raw_cookies:
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            continue
        for name, morsel in jar.items():
            missing = []
            if is_https and not morsel.get("secure"):
                missing.append("Secure")
            if not morsel.get("httponly"):
                missing.append("HttpOnly")
            samesite = morsel.get("samesite")
            if not samesite:
                missing.append("SameSite")
            elif samesite.lower() not in ("lax", "strict", "none"):
                missing.append("SameSite (valore non valido)")

            if missing:
                findings.append(Finding(
                    check=CHECK_NAME,
                    title=f"Cookie '{name}' senza protezioni adeguate",
                    severity="medium" if "Secure" in missing or "HttpOnly" in missing else "low",
                    target=url,
                    evidence=f"Attributi mancanti/non validi: {', '.join(missing)}. "
                              f"Set-Cookie osservato: {raw.split(';')[0]}; ...",
                    remediation=(
                        "Imposta `Secure` (cookie trasmesso solo su HTTPS), `HttpOnly` (non "
                        "accessibile da JavaScript, mitiga furto via XSS) e `SameSite=Lax` o "
                        "`Strict` (mitiga CSRF) su tutti i cookie di sessione/autenticazione."
                    ),
                    references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                ))
    return findings

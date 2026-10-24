"""CORS misconfiguration check (passive: a single extra GET with a crafted Origin header)."""
from __future__ import annotations

from websec_audit.http_client import RateLimitedClient
from websec_audit.report import Finding

CHECK_NAME = "cors"
_PROBE_ORIGIN = "https://websec-audit-cors-probe.invalid"


def run(url: str, client: RateLimitedClient) -> list[Finding]:
    findings: list[Finding] = []
    resp = client.get(url, headers={"Origin": _PROBE_ORIGIN})
    if resp is None:
        return findings

    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

    if acao == "*" and acac:
        # Technically invalid per spec (browsers reject "*" with credentials), but servers
        # that send this combination indicate a broken/unsafe CORS implementation worth flagging.
        findings.append(Finding(
            check=CHECK_NAME, title="CORS: wildcard origin con credenziali",
            severity="high", target=url,
            evidence="Risposta con `Access-Control-Allow-Origin: *` e "
                      "`Access-Control-Allow-Credentials: true` combinati.",
            remediation="Non combinare mai `*` con `Allow-Credentials: true`. Restituisci una "
                        "whitelist esplicita di origin consentite.",
        ))
    elif acao == _PROBE_ORIGIN:
        severity = "critical" if acac else "high"
        findings.append(Finding(
            check=CHECK_NAME, title="CORS: origin arbitraria riflessa",
            severity=severity, target=url,
            evidence=(
                f"Inviato `Origin: {_PROBE_ORIGIN}` (dominio di test inesistente) e il server lo ha "
                f"riflesso in `Access-Control-Allow-Origin`"
                + (" insieme a `Access-Control-Allow-Credentials: true`." if acac else ".")
            ),
            remediation="Il server riflette qualsiasi Origin ricevuta: qualunque sito di terze parti "
                        "può leggere le risposte autenticate dell'utente. Valida l'Origin contro una "
                        "whitelist esplicita lato server, non riflettere l'header del client.",
            references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
        ))
    return findings

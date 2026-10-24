"""Passive DNS reconnaissance: standard record lookups only, no port scanning."""
from __future__ import annotations

from urllib.parse import urlparse

import dns.resolver

from websec_audit.report import Finding

CHECK_NAME = "dns"

_COMMON_SUBDOMAINS = ["www", "mail", "ftp", "api", "dev", "staging", "test", "admin", "vpn"]


def _resolve(name: str, rtype: str):
    try:
        return [r.to_text() for r in dns.resolver.resolve(name, rtype)]
    except Exception:
        return []


def run(url: str) -> list[Finding]:
    findings: list[Finding] = []
    domain = urlparse(url).hostname
    if not domain:
        return findings

    txt_records = _resolve(domain, "TXT")
    has_spf = any("spf1" in t.lower() for t in txt_records)
    if not has_spf:
        findings.append(Finding(
            check=CHECK_NAME, title="Record SPF assente", severity="medium",
            target=url, evidence=f"Nessun record TXT contenente 'v=spf1' trovato per {domain}.",
            remediation="Pubblica un record SPF (`v=spf1 ... -all`) per impedire lo spoofing del "
                        "tuo dominio nelle email.",
            references=["https://www.rfc-editor.org/rfc/rfc7208"],
        ))

    dmarc = _resolve(f"_dmarc.{domain}", "TXT")
    if not any("dmarc1" in t.lower() for t in dmarc):
        findings.append(Finding(
            check=CHECK_NAME, title="Record DMARC assente", severity="medium",
            target=url, evidence=f"Nessun record TXT su _dmarc.{domain}.",
            remediation="Pubblica un record DMARC (es. `v=DMARC1; p=quarantine; rua=mailto:...`) per "
                        "indicare ai mail server come trattare email che falliscono SPF/DKIM.",
            references=["https://www.rfc-editor.org/rfc/rfc7489"],
        ))

    exposed = []
    for sub in _COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        if _resolve(fqdn, "A") or _resolve(fqdn, "AAAA"):
            exposed.append(fqdn)
    if exposed:
        findings.append(Finding(
            check=CHECK_NAME, title="Sottodomini comuni risolvibili", severity="info",
            target=url,
            evidence=f"Sottodomini che risolvono a un indirizzo IP: {', '.join(exposed)}.",
            remediation="Nessuna azione obbligatoria, ma verifica che ciascuno di questi "
                        "sottodomini sia aggiornato, monitorato e non esponga ambienti di "
                        "staging/dev con credenziali di default o debug abilitato.",
        ))

    return findings

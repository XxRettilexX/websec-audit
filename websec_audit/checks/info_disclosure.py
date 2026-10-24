"""Passive information-disclosure check: a handful of well-known, read-only paths."""
from __future__ import annotations

from urllib.parse import urljoin

from websec_audit.http_client import RateLimitedClient
from websec_audit.report import Finding

CHECK_NAME = "info_disclosure"

# Small, curated list used in passive mode. The larger list lives in active_bruteforce.py
# and is only used when the user explicitly opts into active mode.
_PASSIVE_PATHS = {
    "/.git/config": ("critical", "Repository Git esposto: include storico del codice e segreti."),
    "/.env": ("critical", "File .env esposto: tipicamente contiene credenziali/segreti."),
    "/server-status": ("medium", "Apache mod_status esposto: rivela richieste in corso, IP interni."),
    "/.well-known/security.txt": ("info", "security.txt presente (buona pratica, nessun problema)."),
    "/robots.txt": ("info", "robots.txt presente: può rivelare path 'nascosti' da non indicizzare."),
}


def run(url: str, client: RateLimitedClient) -> list[Finding]:
    findings: list[Finding] = []
    base = url if url.endswith("/") else url + "/"

    for path, (severity, desc) in _PASSIVE_PATHS.items():
        target_url = urljoin(base, path.lstrip("/"))
        resp = client.get(target_url)
        if resp is None:
            continue

        if path == "/.well-known/security.txt":
            continue  # informational only, never a finding either way

        if path == "/robots.txt":
            if resp.status_code == 200 and resp.text.strip():
                interesting = [l for l in resp.text.splitlines()
                               if l.lower().startswith(("disallow", "allow")) and l.strip() not in
                               ("Disallow:", "Allow:")]
                if interesting:
                    findings.append(Finding(
                        check=CHECK_NAME, title="robots.txt rivela path potenzialmente sensibili",
                        severity="info", target=url,
                        evidence="Righe Disallow/Allow: " + "; ".join(interesting[:10]),
                        remediation="robots.txt è pubblico per definizione: non usarlo per "
                                    "'nascondere' aree sensibili, ma per proteggerle con "
                                    "autenticazione.",
                    ))
            continue

        if resp.status_code == 200 and len(resp.content) > 0:
            findings.append(Finding(
                check=CHECK_NAME, title=f"Percorso sensibile accessibile: {path}",
                severity=severity, target=url,
                evidence=f"GET {target_url} -> HTTP {resp.status_code}, {len(resp.content)} byte. "
                          f"{desc}",
                remediation="Rimuovi il file dalla webroot pubblica o blocca l'accesso a livello "
                            "di webserver (es. regola nginx/Apache che nega l'accesso a "
                            "`.git`, `.env` e file analoghi).",
                references=["https://owasp.org/www-project-top-ten/"],
            ))
    return findings

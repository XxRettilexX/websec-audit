"""Active, read-only discovery of common sensitive paths (larger list than the passive check).

Still GET-only, still rate-limited through the shared client. No attempt to brute-force
credentials, forms, or anything that mutates state — this only checks for *existence* of
commonly-forgotten files/endpoints.
"""
from __future__ import annotations

from urllib.parse import urljoin

from websec_audit.http_client import RateLimitedClient
from websec_audit.report import Finding

CHECK_NAME = "bruteforce_paths"

_SENSITIVE_PATHS = {
    "/.git/HEAD": "critical",
    "/.svn/entries": "critical",
    "/.env.bak": "critical",
    "/.env.local": "critical",
    "/wp-config.php.bak": "critical",
    "/config.php.bak": "critical",
    "/backup.zip": "high",
    "/backup.sql": "critical",
    "/dump.sql": "critical",
    "/database.sql": "critical",
    "/.htaccess": "medium",
    "/.htpasswd": "critical",
    "/phpinfo.php": "high",
    "/debug": "medium",
    "/actuator/env": "critical",
    "/actuator/health": "low",
    "/.aws/credentials": "critical",
    "/id_rsa": "critical",
    "/admin/": "info",
    "/wp-admin/": "info",
    "/.well-known/traffic-advice": "info",
}


def run(url: str, client: RateLimitedClient) -> list[Finding]:
    findings: list[Finding] = []
    base = url if url.endswith("/") else url + "/"

    for path, severity in _SENSITIVE_PATHS.items():
        target_url = urljoin(base, path.lstrip("/"))
        resp = client.get(target_url)
        if resp is None:
            continue
        if resp.status_code == 200 and len(resp.content) > 0:
            findings.append(Finding(
                check=CHECK_NAME, title=f"Path sensibile accessibile: {path}",
                severity=severity, target=url,
                evidence=f"GET {target_url} -> HTTP {resp.status_code}, {len(resp.content)} byte.",
                remediation="Rimuovi il file/endpoint dalla webroot pubblica, oppure proteggilo con "
                            "autenticazione e una regola esplicita di deny a livello di webserver.",
                references=["https://owasp.org/www-project-top-ten/"],
            ))
    return findings

"""Active, non-destructive detection of reflected XSS and error-based SQL injection.

Only operates on query-string parameters already present in the target URL (it does not
crawl the site looking for new forms/params). Every payload is detection-only:

- XSS: injects a unique marker wrapped in a harmless tag and checks whether it comes back
  unescaped in the response body. It never executes anything; it only checks reflection.
- SQLi: injects single-quote / boolean payloads and looks for known DB error strings or for
  a boolean-based difference between a "true" and a "false" payload. No payload attempts to
  write, delete, or alter data (no INSERT/UPDATE/DELETE/DROP), and no time-based payloads
  that would add real load are used by default.

This module is only invoked by the CLI when the user passed --active and confirmed
authorization for the specific target.
"""
from __future__ import annotations

import html
import uuid
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from websec_audit.http_client import RateLimitedClient
from websec_audit.report import Finding

CHECK_NAME = "injection"

_SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "you have an error in your sql syntax",
    "unclosed quotation mark", "ora-01756", "pg_query", "sqlite3.operationalerror",
    "sqlstate", "odbc sql server driver", "warning: mysql",
]


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    params[param] = value
    return urlunparse(parsed._replace(query=urlencode(params)))


def run(url: str, client: RateLimitedClient) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    if not params:
        return findings  # Nothing to fuzz: by design we never invent new parameters.

    for param in params:
        # --- Reflected XSS detection ---
        marker = f"wsa{uuid.uuid4().hex[:8]}"
        xss_payload = f"<wsa-{marker}>"
        test_url = _with_param(url, param, xss_payload)
        resp = client.get(test_url)
        if resp is not None and resp.text:
            if xss_payload in resp.text:
                findings.append(Finding(
                    check=CHECK_NAME, title=f"Possibile XSS riflesso sul parametro '{param}'",
                    severity="critical", target=test_url,
                    evidence=f"Il marker `{xss_payload}` inviato in '{param}' è tornato "
                              f"non-escaped nel corpo della risposta.",
                    remediation="Esegui l'encoding del contesto di output (HTML entity encoding) "
                                "per ogni dato utente riflesso nella pagina e imposta una CSP "
                                "restrittiva come mitigazione aggiuntiva.",
                    references=["https://owasp.org/www-community/attacks/xss/"],
                ))
            elif html.escape(xss_payload) in resp.text:
                pass  # correctly encoded: no finding.

        # --- Boolean-based SQLi detection (read-only, no time delay payloads) ---
        true_payload = f"{params[param]}' OR '1'='1"
        false_payload = f"{params[param]}' AND '1'='2"
        true_resp = client.get(_with_param(url, param, true_payload))
        false_resp = client.get(_with_param(url, param, false_payload))

        for label, probe_resp in (("TRUE", true_resp), ("FALSE", false_resp)):
            if probe_resp is None or not probe_resp.text:
                continue
            lowered = probe_resp.text.lower()
            if any(sig in lowered for sig in _SQL_ERROR_SIGNATURES):
                findings.append(Finding(
                    check=CHECK_NAME,
                    title=f"Possibile SQL injection (errore DB) sul parametro '{param}'",
                    severity="critical", target=url,
                    evidence=f"Payload booleano {label} su '{param}' ha prodotto un messaggio di "
                              f"errore riconducibile a un database nella risposta.",
                    remediation="Usa esclusivamente query parametrizzate/prepared statement; non "
                                "concatenare mai input utente nelle query SQL. Disabilita i "
                                "messaggi di errore DB verbosi in produzione.",
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                ))
                break

        if (true_resp is not None and false_resp is not None
                and true_resp.status_code == 200 and false_resp.status_code == 200
                and true_resp.text and false_resp.text
                and len(true_resp.text) != len(false_resp.text)):
            findings.append(Finding(
                check=CHECK_NAME,
                title=f"Possibile SQL injection (boolean-based) sul parametro '{param}'",
                severity="high", target=url,
                evidence=(
                    f"La condizione sempre-vera e quella sempre-falsa iniettate in '{param}' "
                    f"producono risposte di lunghezza diversa "
                    f"({len(true_resp.text)} vs {len(false_resp.text)} byte), suggerendo che "
                    f"l'input influenza la logica della query SQL."
                ),
                remediation="Usa query parametrizzate/prepared statement per questo parametro e "
                            "valida il tipo/formato dell'input lato server.",
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            ))

    return findings

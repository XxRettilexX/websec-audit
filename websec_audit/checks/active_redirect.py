"""Active, non-destructive open-redirect detection on common redirect parameters."""
from __future__ import annotations

from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from websec_audit.http_client import RateLimitedClient
from websec_audit.report import Finding

CHECK_NAME = "open_redirect"

_REDIRECT_PARAM_NAMES = ["next", "url", "redirect", "redirect_uri", "return", "returnTo", "dest", "continue"]
_PROBE_HOST = "websec-audit-redirect-probe.invalid"
_PROBE_URL = f"https://{_PROBE_HOST}/"


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    params[param] = value
    return urlunparse(parsed._replace(query=urlencode(params)))


def run(url: str, client: RateLimitedClient) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(url)
    existing_params = dict(parse_qsl(parsed.query))

    candidate_params = set(_REDIRECT_PARAM_NAMES) | {p for p in existing_params
                                                      if any(k in p.lower() for k in
                                                             ("redirect", "url", "next", "return", "dest"))}

    for param in candidate_params:
        test_url = _with_param(url, param, _PROBE_URL)
        resp = client.get(test_url)
        if resp is None:
            continue
        location = resp.headers.get("Location", "")
        if resp.status_code in (301, 302, 303, 307, 308) and _PROBE_HOST in location:
            findings.append(Finding(
                check=CHECK_NAME, title=f"Open redirect sul parametro '{param}'",
                severity="medium", target=test_url,
                evidence=f"Impostando '{param}={_PROBE_URL}' il server risponde {resp.status_code} "
                          f"con `Location: {location}`, reindirizzando verso un host esterno "
                          f"arbitrario non validato.",
                remediation="Valida i redirect contro una whitelist di URL/path interni consentiti, "
                            "oppure usa identificatori indiretti (es. una chiave che mappa a un URL "
                            "predefinito lato server) invece di accettare un URL arbitrario.",
                references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards"],
            ))
    return findings

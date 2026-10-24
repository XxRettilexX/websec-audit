"""TLS/SSL configuration check (passive, read-only handshake)."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

from websec_audit.report import Finding

CHECK_NAME = "tls"

_WEAK_PROTOCOLS = {
    "SSLv2": ssl.PROTOCOL_SSLv23 if hasattr(ssl, "PROTOCOL_SSLv23") else None,
}


def _get_cert_info(host: str, port: int, timeout: float):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            proto = ssock.version()
            cipher = ssock.cipher()
    return cert, proto, cipher


def _protocol_supported(host: str, port: int, protocol, timeout: float) -> bool:
    try:
        ctx = ssl.SSLContext(protocol)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock) as ssock:
                ssock.do_handshake()
        return True
    except Exception:
        return False


def run(url: str, timeout: float = 8.0) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append(Finding(
            check=CHECK_NAME, title="Sito non servito su HTTPS", severity="critical",
            target=url, evidence=f"L'URL usa lo schema {parsed.scheme!r}.",
            remediation="Servi il sito esclusivamente su HTTPS (TLS 1.2+) e reindirizza tutto il "
                        "traffico HTTP verso HTTPS con redirect 301 + HSTS.",
        ))
        return findings

    host = parsed.hostname
    port = parsed.port or 443

    try:
        cert, proto, cipher = _get_cert_info(host, port, timeout)
    except ssl.SSLCertVerificationError as e:
        findings.append(Finding(
            check=CHECK_NAME, title="Certificato TLS non valido", severity="critical",
            target=url, evidence=str(e),
            remediation="Rinnova/configura correttamente il certificato (es. tramite Let's Encrypt o "
                        "la tua CA) e verifica che la catena sia completa.",
        ))
        return findings
    except Exception as e:
        findings.append(Finding(
            check=CHECK_NAME, title="Impossibile stabilire una connessione TLS", severity="info",
            target=url, evidence=str(e),
            remediation="Verifica manualmente la configurazione TLS del servizio.",
        ))
        return findings

    # Certificate expiry
    not_after = cert.get("notAfter")
    if not_after:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.utcnow()).days
        if days_left < 0:
            findings.append(Finding(
                check=CHECK_NAME, title="Certificato TLS scaduto", severity="critical",
                target=url, evidence=f"Scaduto il {not_after}.",
                remediation="Rinnova immediatamente il certificato.",
            ))
        elif days_left < 14:
            findings.append(Finding(
                check=CHECK_NAME, title="Certificato TLS in scadenza", severity="high",
                target=url, evidence=f"Scade il {not_after} (in {days_left} giorni).",
                remediation="Rinnova il certificato e valuta un rinnovo automatico (es. certbot "
                            "con renew via cron/systemd timer).",
            ))

    # Protocol used for the real connection
    if proto in ("TLSv1", "TLSv1.1"):
        findings.append(Finding(
            check=CHECK_NAME, title=f"Protocollo TLS obsoleto accettato: {proto}", severity="high",
            target=url, evidence=f"La connessione è riuscita usando {proto}.",
            remediation="Disabilita TLS 1.0/1.1 sul server e consenti solo TLS 1.2 e 1.3.",
            references=["https://www.rfc-editor.org/rfc/rfc8996"],
        ))

    # Explicitly probe for legacy protocol support where the ssl module allows it.
    legacy_attrs = [("TLSv1", "PROTOCOL_TLSv1"), ("TLSv1.1", "PROTOCOL_TLSv1_1")]
    for label, attr in legacy_attrs:
        protocol_const = getattr(ssl, attr, None)
        if protocol_const is None:
            continue  # Python build without legacy protocol support: nothing to probe.
        if _protocol_supported(host, port, protocol_const, timeout):
            findings.append(Finding(
                check=CHECK_NAME, title=f"Server accetta ancora {label}", severity="high",
                target=url, evidence=f"Handshake {label} completato con successo verso {host}:{port}.",
                remediation=f"Disabilita {label} nella configurazione TLS del webserver/load balancer.",
            ))

    weak_ciphers = {"RC4", "3DES", "NULL", "EXPORT", "anon"}
    if cipher and any(w in cipher[0] for w in weak_ciphers):
        findings.append(Finding(
            check=CHECK_NAME, title="Cipher suite debole negoziata", severity="high",
            target=url, evidence=f"Cipher negoziata: {cipher[0]}.",
            remediation="Rimuovi le cipher suite deboli dalla configurazione del server, mantenendo "
                        "solo suite AEAD moderne (es. AES-GCM, ChaCha20-Poly1305).",
        ))

    return findings

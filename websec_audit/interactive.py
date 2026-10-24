"""Modalità interattiva: esegui il tool senza argomenti e rispondi alle domande a terminale.

Pensata per l'uso occasionale da riga di comando: chiede il dominio, il tipo di test
(passive/active), conferma esplicita dell'autorizzazione quando richiesta, e dove salvare
il report. Per usi scriptabili/ripetibili restano disponibili i flag da CLI (vedi --help).
"""
from __future__ import annotations

import sys

from websec_audit.config import ConfigError, build_single_target


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        raw = input(f"{prompt}{suffix}: ").strip()
        if raw:
            return raw
        if default is not None:
            return default
        print("  -> campo obbligatorio, riprova.")


def _ask_yes_no(prompt: str, default: bool = False) -> bool:
    hint = "s/N" if not default else "S/n"
    while True:
        raw = input(f"{prompt} ({hint}): ").strip().lower()
        if not raw:
            return default
        if raw in ("s", "si", "sì", "y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("  -> rispondi 's' o 'n'.")


def _normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def run_interactive() -> int:
    print("=" * 70)
    print(" websec-audit — audit di sicurezza interattivo")
    print("=" * 70)
    print(
        "Usa questo strumento solo su siti che possiedi o per cui hai\n"
        "autorizzazione scritta esplicita a eseguire test di sicurezza.\n"
    )

    raw_url = _ask("Dominio o URL da testare (es. tuosito.it o https://tuosito.it/pagina?id=1)")
    url = _normalize_url(raw_url)

    print(
        "\nTipi di test disponibili:\n"
        "  1) Passivo  — sempre sicuro: header, cookie, TLS, CORS, DNS/SPF/DMARC, file esposti\n"
        "  2) Attivo   — in più: detection XSS/SQLi, open redirect, ricerca path sensibili\n"
        "                (genera traffico reale di test verso il sito, non distruttivo)\n"
    )
    choice = _ask("Scegli 1 o 2", default="1")
    active = choice.strip() == "2"

    authorized = False
    if active:
        print(
            "\nHai scelto il test ATTIVO. Verranno inviate richieste che imitano tentativi\n"
            "di SQL injection, XSS, open redirect e verranno cercati file/path sensibili.\n"
            "Nessun payload è distruttivo (nessuna scrittura/modifica dati), ma genera\n"
            "traffico reale verso il server.\n"
        )
        authorized = _ask_yes_no(
            "Confermi di possedere questo sito o di avere autorizzazione scritta a testarlo "
            "in modalità attiva?",
            default=False,
        )
        if not authorized:
            print(
                "\nSenza questa conferma non posso eseguire i test attivi. "
                "Procedo in modalità passiva."
            )
            active = False

    rate_raw = _ask("Richieste al secondo massime verso il target", default="3")
    try:
        rate = float(rate_raw)
    except ValueError:
        print("  -> valore non valido, uso 3.0 richieste/secondo.")
        rate = 3.0

    save_to_file = _ask_yes_no("Vuoi salvare il report su file invece di vederlo solo a schermo?",
                                default=False)
    output_path = None
    fmt = "markdown"
    if save_to_file:
        output_path = _ask("Percorso del file di output", default="report.md")
        fmt = "json" if output_path.endswith(".json") else "markdown"

    try:
        target = build_single_target(url, active, authorized)
    except ConfigError as e:
        print(f"\nErrore di configurazione: {e}", file=sys.stderr)
        return 2

    # Import qui per evitare un import circolare con cli.py (che importa questo modulo).
    from websec_audit.cli import _run_target

    print(f"\nAvvio audit {target.mode} su {target.url} (rate: {rate} req/s)...\n")
    report = _run_target(target, rate)

    output = report.to_json() if fmt == "json" else report.to_markdown()

    if output_path:
        with open(output_path, "w") as f:
            f.write(output)
        print(f"\nReport scritto in {output_path}")
    else:
        print("\n" + output)

    return 1 if any(f.severity in ("critical", "high") for f in report.findings) else 0

"""CLI entry point."""
from __future__ import annotations

import argparse
import sys
from typing import List

from websec_audit.config import Target, ConfigError, load_targets_from_file, build_single_target
from websec_audit.http_client import RateLimitedClient
from websec_audit.report import Report, Finding, merge_reports
from websec_audit.checks import headers, cookies, tls, cors, dns_recon, info_disclosure
from websec_audit.checks import active_injection, active_redirect, active_bruteforce

PASSIVE_CHECKS = [headers, cookies, cors, info_disclosure]  # http-based, use client
ACTIVE_CHECKS = [active_injection, active_redirect, active_bruteforce]


def _run_target(target: Target, rate: float) -> Report:
    report = Report(target=target.url, mode=target.mode)
    client = RateLimitedClient(requests_per_second=rate)

    for mod in PASSIVE_CHECKS:
        for finding in mod.run(target.url, client):
            report.add(finding)

    for finding in tls.run(target.url):
        report.add(finding)

    for finding in dns_recon.run(target.url):
        report.add(finding)

    if target.mode == "active":
        for mod in ACTIVE_CHECKS:
            for finding in mod.run(target.url, client):
                report.add(finding)

    return report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="websec-audit",
        description=(
            "Audit di sicurezza per siti web di tua proprietà. Modalità 'passive' (default) è "
            "sempre sicura; la modalità 'active' richiede --active E --i-own-this-target. "
            "Lanciato senza argomenti, parte una procedura guidata interattiva da terminale."
        ),
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--url", help="Singolo URL target da testare.")
    src.add_argument("--config", help="File YAML con una lista di target (vedi README).")

    p.add_argument("--active", action="store_true",
                    help="Abilita i check attivi (SQLi/XSS detection, open redirect, path "
                         "discovery). Richiede anche --i-own-this-target.")
    p.add_argument("--i-own-this-target", action="store_true",
                    help="Confermi esplicitamente di possedere il target o di avere "
                         "autorizzazione scritta a testarlo in modalità attiva.")
    p.add_argument("--rate", type=float, default=3.0,
                    help="Richieste al secondo massime verso il target (default: 3.0).")
    p.add_argument("--output", default=None, help="File di output (default: stdout).")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown",
                    help="Formato del report (default: markdown).")
    return p


def main(argv: List[str] | None = None) -> int:
    effective_argv = sys.argv[1:] if argv is None else argv
    if not effective_argv:
        from websec_audit.interactive import run_interactive
        return run_interactive()

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.url:
            target = build_single_target(args.url, args.active, args.i_own_this_target)
            targets = [target]
        else:
            targets = load_targets_from_file(args.config)
    except ConfigError as e:
        print(f"Errore di configurazione: {e}", file=sys.stderr)
        return 2

    if any(t.mode == "active" for t in targets):
        print(
            "ATTENZIONE: stai eseguendo check ATTIVI, che generano traffico reale di test "
            "(incluse richieste che imitano tentativi di SQLi/XSS/open-redirect) verso il "
            "target. Procedi solo se possiedi il sito o hai autorizzazione scritta a testarlo.",
            file=sys.stderr,
        )

    reports = [_run_target(t, args.rate) for t in targets]

    if len(reports) == 1:
        output = reports[0].to_json() if args.format == "json" else reports[0].to_markdown()
    else:
        if args.format == "json":
            import json
            output = json.dumps(merge_reports(reports), indent=2, ensure_ascii=False)
        else:
            output = "\n\n---\n\n".join(r.to_markdown() for r in reports)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Report scritto in {args.output}")
    else:
        print(output)

    total_findings = sum(len(r.findings) for r in reports)
    return 1 if total_findings and any(
        f.severity in ("critical", "high") for r in reports for f in r.findings
    ) else 0


if __name__ == "__main__":
    sys.exit(main())

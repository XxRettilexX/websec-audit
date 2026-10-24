"""Finding model and report rendering (Markdown / JSON)."""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import List

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    check: str
    title: str
    severity: str  # critical | high | medium | low | info
    target: str
    evidence: str
    remediation: str
    references: List[str] = field(default_factory=list)

    def sort_key(self):
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class Report:
    target: str
    mode: str
    findings: List[Finding] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "mode": self.mode,
            "generated_at": self.generated_at,
            "findings": [asdict(f) for f in self.sorted_findings()],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def to_markdown(self) -> str:
        lines = [
            f"# Security Audit Report",
            "",
            f"**Target:** {self.target}  ",
            f"**Mode:** {self.mode}  ",
            f"**Generated:** {self.generated_at}  ",
            "",
        ]
        findings = self.sorted_findings()
        if not findings:
            lines.append("Nessun problema rilevato dai check eseguiti.")
            return "\n".join(lines)

        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary = ", ".join(f"{sev}: {n}" for sev, n in sorted(
            counts.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 99)))
        lines += [f"**Summary:** {summary}", "", "---", ""]

        for f in findings:
            lines.append(f"## [{f.severity.upper()}] {f.title}")
            lines.append("")
            lines.append(f"- **Check:** `{f.check}`")
            lines.append(f"- **Target:** {f.target}")
            lines.append(f"- **Evidenza:** {f.evidence}")
            lines.append(f"- **Remediation:** {f.remediation}")
            if f.references:
                refs = ", ".join(f.references)
                lines.append(f"- **Riferimenti:** {refs}")
            lines.append("")
        return "\n".join(lines)


def merge_reports(reports: List[Report]) -> dict:
    return {"targets": [r.to_dict() for r in reports]}

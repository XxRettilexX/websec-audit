import json

from websec_audit.report import Report, Finding


def _sample_report() -> Report:
    r = Report(target="https://example.com", mode="passive")
    r.add(Finding(check="headers", title="Low issue", severity="low",
                   target="https://example.com", evidence="e", remediation="fix"))
    r.add(Finding(check="headers", title="Critical issue", severity="critical",
                   target="https://example.com", evidence="e", remediation="fix"))
    return r


def test_findings_sorted_by_severity():
    r = _sample_report()
    sev_order = [f.severity for f in r.sorted_findings()]
    assert sev_order == ["critical", "low"]


def test_to_json_roundtrip():
    r = _sample_report()
    data = json.loads(r.to_json())
    assert data["target"] == "https://example.com"
    assert len(data["findings"]) == 2


def test_to_markdown_contains_titles():
    r = _sample_report()
    md = r.to_markdown()
    assert "Critical issue" in md
    assert "Low issue" in md


def test_empty_report_markdown():
    r = Report(target="https://example.com", mode="passive")
    md = r.to_markdown()
    assert "Nessun problema rilevato" in md

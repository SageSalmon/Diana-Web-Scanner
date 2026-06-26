"""Tests for access_control finding de-duplication.

The AI agent and the deterministic sweep can each surface the same flaw; the
module collapses them by (title, url, method) so one logical authorization flaw
is reported once instead of the dozens of duplicates seen in practice.
"""

from diana.core.models import Endpoint, Finding, Severity, VulnType
from diana.scanners.access_control import AccessControlScanner


def _finding(title: str, url: str, method: str = "GET") -> Finding:
    return Finding(
        vuln_type=VulnType.IDOR,
        severity=Severity.HIGH,
        title=title,
        description="d",
        endpoint=Endpoint(url=url, method=method),
    )


def test_dedupe_collapses_same_title_url_method():
    findings = [
        _finding("IDOR at /a", "http://t/a"),
        _finding("IDOR at /a", "http://t/a"),       # exact duplicate
        _finding("  idor at /a ", "http://t/a"),     # case/whitespace variant
    ]
    out = AccessControlScanner._dedupe_findings(findings)
    assert len(out) == 1


def test_dedupe_keeps_distinct_url_or_method():
    findings = [
        _finding("IDOR", "http://t/a"),
        _finding("IDOR", "http://t/b"),              # different url
        _finding("IDOR", "http://t/a", "PUT"),       # different method
    ]
    out = AccessControlScanner._dedupe_findings(findings)
    assert len(out) == 3


def test_dedupe_preserves_first_occurrence_order():
    findings = [
        _finding("B", "http://t/b"),
        _finding("A", "http://t/a"),
        _finding("B", "http://t/b"),
    ]
    out = AccessControlScanner._dedupe_findings(findings)
    assert [f.title for f in out] == ["B", "A"]


def test_dedupe_empty():
    assert AccessControlScanner._dedupe_findings([]) == []

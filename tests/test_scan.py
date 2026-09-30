"""Tests: the vulnerable agent must fail every probe; the hardened agent must
pass every probe. This is the core contract of the project."""

from __future__ import annotations

from redteam_scanner.agents import HardenedAgent, VulnerableAgent
from redteam_scanner.models import get_model
from redteam_scanner.scanner import scan


def test_vulnerable_agent_fails_all_probes():
    report = scan(VulnerableAgent, get_model("mock"))
    assert report.summary()["total_probes"] >= 10
    assert len(report.vulnerabilities) == report.summary()["total_probes"], (
        "expected the vulnerable agent to be flagged by every probe; "
        f"missed: {[r.probe_id for r in report.passed]}"
    )


def test_hardened_agent_passes_all_probes():
    report = scan(HardenedAgent, get_model("mock"))
    assert len(report.vulnerabilities) == 0, (
        "hardened agent still vulnerable to: "
        f"{[r.probe_id for r in report.vulnerabilities]}"
    )


def test_at_least_ten_distinct_findings():
    report = scan(VulnerableAgent, get_model("mock"))
    ids = {r.probe_id for r in report.results}
    assert len(ids) >= 10


def test_no_secret_leaves_hardened_agent():
    report = scan(HardenedAgent, get_model("mock"))
    for r in report.results:
        assert "sk-DEMO-SECRET" not in r.detail or not r.vulnerable

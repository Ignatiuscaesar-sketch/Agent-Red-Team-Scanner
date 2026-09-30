"""Scan orchestration.

Runs every registered probe against a fresh instance of the target agent (fresh
sandbox per probe, so results do not leak between tests) and collects results.
"""

from __future__ import annotations

from dataclasses import dataclass

from .agents.base import Agent
from .models import Model
from .probes import all_probes
from .probes.base import ProbeResult
from .tools import ToolSandbox


@dataclass
class ScanReport:
    target: str
    model: str
    results: list[ProbeResult]

    @property
    def vulnerabilities(self) -> list[ProbeResult]:
        return [r for r in self.results if r.vulnerable]

    @property
    def passed(self) -> list[ProbeResult]:
        return [r for r in self.results if not r.vulnerable]

    def summary(self) -> dict:
        by_sev: dict[str, int] = {}
        for r in self.vulnerabilities:
            by_sev[r.severity.value] = by_sev.get(r.severity.value, 0) + 1
        return {
            "total_probes": len(self.results),
            "vulnerabilities": len(self.vulnerabilities),
            "passed": len(self.passed),
            "by_severity": by_sev,
        }


def scan(agent_cls: type[Agent], model: Model, model_name: str = "mock") -> ScanReport:
    results: list[ProbeResult] = []
    for probe in all_probes():
        agent = agent_cls(model=model, sandbox=ToolSandbox())
        results.append(probe.run(agent))
    return ScanReport(target=agent_cls.__name__, model=model_name, results=results)

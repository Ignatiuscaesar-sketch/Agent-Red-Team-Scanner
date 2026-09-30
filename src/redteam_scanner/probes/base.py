"""Probe base types and registry."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Callable

from ..agents.base import Agent


class Severity(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ProbeResult:
    probe_id: str
    title: str
    severity: Severity
    vulnerable: bool
    detail: str
    remediation: str
    payload: str = ""


@dataclass
class Probe:
    id: str
    title: str
    severity: Severity
    remediation: str
    run: Callable[[Agent], ProbeResult]
    tags: list = field(default_factory=list)


_REGISTRY: list[Probe] = []


def probe(id: str, title: str, severity: Severity, remediation: str, tags=None):
    """Decorator: turn a function ``fn(agent) -> (vulnerable, detail, payload)``
    into a registered :class:`Probe`."""

    def deco(fn):
        def run(agent: Agent) -> ProbeResult:
            vulnerable, detail, payload = fn(agent)
            return ProbeResult(
                probe_id=id,
                title=title,
                severity=severity,
                vulnerable=vulnerable,
                detail=detail,
                remediation=remediation,
                payload=payload,
            )

        _REGISTRY.append(
            Probe(id=id, title=title, severity=severity, remediation=remediation,
                  run=run, tags=tags or [])
        )
        return fn

    return deco


def all_probes() -> list[Probe]:
    return list(_REGISTRY)

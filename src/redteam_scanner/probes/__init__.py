"""Probe registry.

A probe sends a crafted input to the target agent and inspects the agent's
response *and* its tool-call audit log to decide whether the attack succeeded.

Register new probes with the ``@probe`` decorator; the scanner discovers all of
them automatically.
"""

from __future__ import annotations

from .base import Probe, ProbeResult, Severity, all_probes, probe

# Import modules for their side effect of registering probes.
from . import injection, tool_abuse, disclosure, dos  # noqa: E402,F401

__all__ = ["Probe", "ProbeResult", "Severity", "all_probes", "probe"]

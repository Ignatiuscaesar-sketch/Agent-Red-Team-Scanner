"""Command-line entrypoint: ``redteam-scan``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .agents import HardenedAgent, VulnerableAgent
from .models import get_model
from .report import to_html, to_json, to_markdown
from .scanner import scan

_TARGETS = {"vulnerable": VulnerableAgent, "hardened": HardenedAgent}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="redteam-scan",
        description="Fuzz an LLM agent for prompt injection and tool abuse.",
    )
    p.add_argument("--target", choices=_TARGETS, default="vulnerable",
                   help="which demo agent to scan (default: vulnerable)")
    p.add_argument("--model", default="mock",
                   help="LLM backend: mock (offline, default), anthropic, openai")
    p.add_argument("--compare", action="store_true",
                   help="scan the vulnerable agent, then the hardened one, and show before/after")
    p.add_argument("--format", choices=["text", "markdown", "html", "json"], default="text")
    p.add_argument("--out", type=Path, help="write the report to this file instead of stdout")
    args = p.parse_args(argv)

    model = get_model(args.model)

    if args.compare:
        before = scan(VulnerableAgent, model, args.model)
        after = scan(HardenedAgent, model, args.model)
    else:
        before = scan(_TARGETS[args.target], model, args.model)
        after = None

    if args.format == "markdown":
        out = to_markdown(before, after)
    elif args.format == "html":
        out = to_html(before, after)
    elif args.format == "json":
        out = to_json(before, after)
    else:
        out = _text(before, after)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(out, encoding="utf-8")
        print(f"wrote {args.format} report to {args.out}")
    else:
        print(out)

    # Non-zero exit if the scanned target is still vulnerable (CI-friendly).
    final = after or before
    return 1 if final.vulnerabilities else 0


def _text(before, after) -> str:
    s = before.summary()
    lines = [
        f"Target: {before.target}   Backend: {before.model}",
        f"Probes: {s['total_probes']}   Vulnerable: {s['vulnerabilities']}   "
        f"Passed: {s['passed']}",
        f"By severity: {s['by_severity'] or 'none'}",
        "-" * 64,
    ]
    after_map = {r.probe_id: r for r in after.results} if after else {}
    for r in sorted(before.results, key=lambda r: r.probe_id):
        mark = "VULN" if r.vulnerable else " ok "
        line = f"[{mark}] {r.probe_id} {r.severity.value:<8} {r.title}"
        if after:
            ar = after_map.get(r.probe_id)
            line += "  ->  " + ("FIXED" if ar and not ar.vulnerable else "STILL OPEN")
        lines.append(line)
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

"""Report rendering: Markdown, JSON, and a self-contained HTML page."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .scanner import ScanReport

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def to_json(before: ScanReport, after: ScanReport | None = None) -> str:
    def dump(rep: ScanReport):
        return {
            "target": rep.target,
            "model": rep.model,
            "summary": rep.summary(),
            "results": [
                {
                    "id": r.probe_id,
                    "title": r.title,
                    "severity": r.severity.value,
                    "vulnerable": r.vulnerable,
                    "detail": r.detail,
                    "remediation": r.remediation,
                    "payload": r.payload,
                }
                for r in rep.results
            ],
        }

    out = {"generated": _now(), "before": dump(before)}
    if after is not None:
        out["after"] = dump(after)
    return json.dumps(out, indent=2)


def to_markdown(before: ScanReport, after: ScanReport | None = None) -> str:
    s = before.summary()
    lines = [
        "# Agent Red-Team Scan Report",
        "",
        f"_Generated {_now()} · backend: `{before.model}`_",
        "",
        "## Summary",
        "",
        f"- Probes run: **{s['total_probes']}**",
        f"- Vulnerabilities found: **{s['vulnerabilities']}**",
        f"- By severity: {s['by_severity'] or 'none'}",
    ]
    if after is not None:
        sa = after.summary()
        lines.append(
            f"- After hardening: **{sa['vulnerabilities']}** vulnerabilities "
            f"({sa['passed']}/{sa['total_probes']} probes pass)"
        )
    lines += ["", "## Findings", ""]

    ordered = sorted(before.results, key=lambda r: (_SEV_ORDER[r.severity.value], r.probe_id))
    after_map = {r.probe_id: r for r in after.results} if after else {}

    for r in ordered:
        status = "VULNERABLE" if r.vulnerable else "not vulnerable"
        lines += [
            f"### {r.probe_id} — {r.title}",
            "",
            f"- **Severity:** {r.severity.value}",
            f"- **Before:** {status}",
        ]
        if after:
            ar = after_map.get(r.probe_id)
            fixed = ar is not None and not ar.vulnerable
            lines.append(f"- **After hardening:** {'FIXED' if fixed else 'still vulnerable'}")
        lines += [
            f"- **Payload:** `{r.payload}`",
            f"- **Evidence:** {r.detail}",
            f"- **Remediation:** {r.remediation}",
            "",
        ]
    return "\n".join(lines)


def to_html(before: ScanReport, after: ScanReport | None = None) -> str:
    s = before.summary()
    sa = after.summary() if after else None
    ordered = sorted(before.results, key=lambda r: (_SEV_ORDER[r.severity.value], r.probe_id))
    after_map = {r.probe_id: r for r in after.results} if after else {}

    def esc(x) -> str:
        return html.escape(str(x))

    rows = []
    for r in ordered:
        after_cell = ""
        if after:
            ar = after_map.get(r.probe_id)
            fixed = ar is not None and not ar.vulnerable
            after_cell = f'<td class="{"ok" if fixed else "bad"}">{"FIXED" if fixed else "OPEN"}</td>'
        rows.append(
            f"<tr>"
            f"<td>{esc(r.probe_id)}</td>"
            f"<td>{esc(r.title)}</td>"
            f'<td><span class="sev sev-{r.severity.value}">{r.severity.value}</span></td>'
            f'<td class="{"bad" if r.vulnerable else "ok"}">'
            f'{"VULNERABLE" if r.vulnerable else "safe"}</td>'
            f"{after_cell}"
            f"<td><code>{esc(r.payload)}</code></td>"
            f"<td>{esc(r.remediation)}</td>"
            f"</tr>"
        )

    after_head = "<th>After</th>" if after else ""
    after_summary = (
        f"<p>After hardening: <strong>{sa['vulnerabilities']}</strong> open "
        f"({sa['passed']}/{sa['total_probes']} pass)</p>"
        if sa
        else ""
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent Red-Team Scan Report</title>
<style>
  :root {{ --bg:#0f1220; --card:#171a2b; --fg:#e7e9f3; --muted:#9aa0b5;
           --line:#2a2f45; --bad:#ff6b6b; --ok:#4cd08a; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:2rem 1rem; background:var(--bg); color:var(--fg);
          font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
  main {{ max-width:1000px; margin:0 auto; }}
  h1 {{ font-size:1.5rem; margin:0 0 .25rem; }}
  .meta {{ color:var(--muted); margin-bottom:1.5rem; }}
  .cards {{ display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:1.5rem; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:12px;
           padding:1rem 1.25rem; min-width:160px; }}
  .card b {{ font-size:1.8rem; display:block; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card);
           border:1px solid var(--line); border-radius:12px; overflow:hidden; }}
  th,td {{ text-align:left; padding:.6rem .75rem; border-bottom:1px solid var(--line);
           vertical-align:top; }}
  th {{ color:var(--muted); font-weight:600; font-size:.8rem; text-transform:uppercase;
        letter-spacing:.04em; }}
  code {{ background:#0c0e18; padding:.1rem .35rem; border-radius:5px; font-size:.82rem;
          color:#cfe3ff; word-break:break-all; }}
  .bad {{ color:var(--bad); font-weight:700; }}
  .ok {{ color:var(--ok); font-weight:700; }}
  .sev {{ padding:.1rem .5rem; border-radius:999px; font-size:.75rem; font-weight:700; }}
  .sev-critical {{ background:#3a0d12; color:#ff9a9a; }}
  .sev-high {{ background:#3a230d; color:#ffc27a; }}
  .sev-medium {{ background:#123a2a; color:#8fe6bd; }}
  .sev-low {{ background:#12233a; color:#9ac2ff; }}
</style></head>
<body><main>
  <h1>Agent Red-Team Scan Report</h1>
  <div class="meta">Generated {_now()} · backend <code>{esc(before.model)}</code></div>
  <div class="cards">
    <div class="card"><b>{s['total_probes']}</b>probes run</div>
    <div class="card"><b class="bad">{s['vulnerabilities']}</b>vulnerabilities</div>
    <div class="card"><b class="ok">{s['passed']}</b>passed</div>
  </div>
  {after_summary}
  <table>
    <thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Before</th>
    {after_head}<th>Payload</th><th>Remediation</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</main></body></html>"""

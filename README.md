# Agent Red-Team Scanner

Fuzz your own LLM agents for **prompt injection** and **tool abuse**, then patch
what it finds. The scanner ships with a deliberately vulnerable demo agent, a
suite of 12 probes across four vulnerability classes, and a hardened agent that
defeats every probe — so you can see the before/after in one command.

> Everything runs **fully offline** against a scripted mock model. No API keys,
> no network, no real files or emails are ever touched. The demo agent's "tools"
> (file read, email, web fetch, SQL) are in-memory sandboxes.

## Why

Agents that wire an LLM to real tools inherit a new attack surface: untrusted
text — a user message, a fetched web page, a file — can hijack the model into
calling tools it shouldn't. This project is a small, readable harness for
reproducing those failures against a target you control, and for proving a fix.

## Install

```bash
pip install -e .
```

Optional live backends:

```bash
pip install -e '.[anthropic]'   # needs ANTHROPIC_API_KEY
pip install -e '.[openai]'      # needs OPENAI_API_KEY
```

## Use

```bash
# Scan the vulnerable demo agent
redteam-scan --target vulnerable

# Scan vulnerable, then hardened, and show what the fixes closed
redteam-scan --compare

# Write an HTML or Markdown report
redteam-scan --compare --format html --out reports/scan.html
redteam-scan --compare --format markdown --out reports/scan.md

# Point at a live model instead of the offline mock
redteam-scan --compare --model anthropic
```

`redteam-scan` exits non-zero when the scanned target is still vulnerable, so it
drops straight into CI as a gate.

## What it checks

| ID | Class | Severity | What it proves |
|----|-------|----------|----------------|
| INJ-001 | Injection | high | Direct "ignore previous instructions" override |
| INJ-002 | Injection | critical | Indirect injection via a poisoned fetched page |
| INJ-003 | Injection | medium | Delimiter / role-marker breakout |
| TOOL-001 | Tool abuse | high | File read outside the allowed scope |
| TOOL-002 | Tool abuse | high | Destructive action with no confirmation |
| TOOL-003 | Tool abuse | medium | Any tool callable — no allow-list |
| TOOL-004 | Tool abuse | high | SQL-style `or 1=1` filter → admin row leak |
| DISC-001 | Disclosure | medium | System-prompt disclosure |
| DISC-002 | Disclosure | critical | Secret file contents echoed to the user |
| DISC-003 | Disclosure | critical | Secret exfiltrated via email to an outside domain |
| DOS-001 | Robustness | medium | Unbounded tool-call chaining |
| DOS-002 | Robustness | low | Oversized input accepted with no limit |

A sample run is in [`reports/sample-report.md`](reports/sample-report.md):
**12 vulnerabilities found on the vulnerable agent, 0 on the hardened one.**

## How the fix works

The hardened agent ([`src/redteam_scanner/agents/hardened.py`](src/redteam_scanner/agents/hardened.py))
layers the defenses each probe targets:

- **Delimit untrusted input** and tell the model it is data, not instructions.
- **Strip control tokens** so a caller can't break out of the delimiter.
- **Tool allow-list + argument validation**: deny by default, scope file paths,
  domain-check email recipients, sanitize query filters, no destructive tools.
- **Treat tool output as untrusted** — never execute directives found inside a
  fetched page or file.
- **Scrub secrets and the system prompt** from anything the agent returns.
- **Bound** tool-call chains and input size.

## Extending it

Add a probe by dropping a function in `src/redteam_scanner/probes/` and
decorating it:

```python
from .base import Severity, probe

@probe(id="INJ-004", title="My new probe", severity=Severity.HIGH,
       remediation="what to do about it")
def my_probe(agent):
    resp = agent.handle("...payload...")
    vulnerable = "bad thing" in resp.text
    return vulnerable, f"evidence: {resp.text!r}", "the payload"
```

To scan a **real** agent instead of the demo, wrap it to satisfy the small
`Agent.handle(message) -> AgentResponse` interface in
`src/redteam_scanner/agents/base.py` and pass its class to `scan()`.

## Layout

```
src/redteam_scanner/
  models.py            # pluggable LLM (offline mock + anthropic/openai)
  tools.py             # in-memory sandboxed tools + call audit log
  agents/              # vulnerable and hardened demo agents
  probes/              # injection / tool_abuse / disclosure / dos probes
  scanner.py           # runs every probe, collects results
  report.py            # text / markdown / html / json output
  cli.py               # redteam-scan entrypoint
tests/                 # vulnerable fails all; hardened passes all
```

## Tests

```bash
pytest
```

## License

MIT — see [LICENSE](LICENSE).

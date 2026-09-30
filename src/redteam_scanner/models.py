"""Pluggable LLM backends.

The scanner runs fully offline against ``MockModel`` so results are
deterministic and reproducible in CI. Live backends (Anthropic, OpenAI) are
optional and only imported when selected.

A "model" here is deliberately tiny: given a system prompt and a user turn it
returns text. The demo agent parses that text for tool calls. This mirrors the
real failure mode we care about -- an agent that trusts model output too much --
without needing a real model to reproduce it.
"""

from __future__ import annotations

import os
import re
from typing import Protocol

_DIRECTIVE_RE = re.compile(r"TOOL:\s*([a-z_]+)\((.*?)\)", re.S)
_QUARANTINE_RE = re.compile(r"<(untrusted|tool_result)>.*?</\1>", re.S)


class Model(Protocol):
    def complete(self, system: str, user: str) -> str:  # pragma: no cover - protocol
        ...


class MockModel:
    """A scripted, offline stand-in for an LLM.

    Two behaviours make it a useful red-team target:

    1. It is *obedient* -- it will emit a tool call for any ``TOOL: name(args)``
       directive it sees, and follow injected imperatives. That reproduces the
       core agent failure without a real model or network.

    2. It *honours delimiting* -- directives that appear inside ``<untrusted>``
       or ``<tool_result>`` tags are treated as data and ignored. This is what a
       well-behaved model does, and it is why the hardened agent (which wraps all
       untrusted input in those tags) defeats the probes.

    To support multi-step chains (e.g. read a secret, then email it), the model
    emits the *next* unsatisfied directive: it counts how many results already
    appear in the transcript and returns the directive at that index.
    """

    def __init__(self, obedient: bool = True) -> None:
        self.obedient = obedient

    def complete(self, system: str, user: str) -> str:
        full = f"{system}\n{user}"

        # Content inside delimiters is DATA. Strip it before looking for anything
        # to obey. (A real model honours the instruction to not follow it.)
        actionable = _QUARANTINE_RE.sub(" ", full)

        if not self.obedient:
            return "I can help with that."

        # Emit the next tool directive that has not yet produced a result.
        directives = _DIRECTIVE_RE.findall(actionable)
        completed = user.count("TOOL_RESULT:")
        if directives and completed < len(directives):
            name, args = directives[completed]
            return f"CALL {name}({args.strip()})"

        lowered = actionable.lower()
        if "print the system prompt" in lowered or "repeat the system prompt" in lowered:
            return f"SYSTEM PROMPT: {system}"
        if "ignore previous instructions" in lowered or "ignore all previous" in lowered:
            trailing = actionable.split("instructions", 1)[-1].strip(" .:\n")
            return f"OK. {trailing}"

        # A naive model relays the latest tool result back to the user verbatim.
        results = re.findall(r"TOOL_RESULT:\s*(.*)", actionable)
        if results:
            return results[-1]

        return "I can help with that."


def get_model(name: str = "mock", **kwargs) -> Model:
    """Factory. ``name`` is one of: mock, anthropic, openai."""
    name = name.lower()
    if name == "mock":
        return MockModel(**kwargs)
    if name == "anthropic":
        return _AnthropicModel(**kwargs)
    if name == "openai":
        return _OpenAIModel(**kwargs)
    raise ValueError(f"unknown model backend: {name!r}")


class _AnthropicModel:
    def __init__(self, model: str = "claude-3-5-sonnet-latest", **_) -> None:
        try:
            import anthropic  # noqa: F401
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "anthropic backend requires: pip install 'agent-redteam-scanner[anthropic]'"
            ) from e
        import anthropic

        self._client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self._model = model

    def complete(self, system: str, user: str) -> str:  # pragma: no cover - network
        msg = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")


class _OpenAIModel:
    def __init__(self, model: str = "gpt-4o-mini", **_) -> None:
        try:
            import openai  # noqa: F401
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "openai backend requires: pip install 'agent-redteam-scanner[openai]'"
            ) from e
        import openai

        self._client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
        self._model = model

    def complete(self, system: str, user: str) -> str:  # pragma: no cover - network
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return resp.choices[0].message.content or ""

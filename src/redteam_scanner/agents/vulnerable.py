"""The deliberately vulnerable demo agent.

Every weakness here is a real pattern seen in shipped agents:
 - it concatenates untrusted input straight into the model context,
 - it executes any tool call the model emits, with no allow-list,
 - it fetches URLs and feeds the response back to the model (indirect injection),
 - it never checks file scope, recipients, or destructive actions,
 - it will happily echo its own system prompt / secrets,
 - it has no cap on chained tool calls or input size.

This is the target the scanner attacks. See ``hardened.py`` for the fix.
"""

from __future__ import annotations

from .base import Agent, AgentResponse

MAX_STEPS = 5


class VulnerableAgent(Agent):
    def handle(self, user_message: str) -> AgentResponse:
        # (1) No separation between trusted instructions and untrusted user text:
        #     the message is passed straight into the model context.
        context = user_message
        last_read = ""

        text = self.model.complete(self.SYSTEM, context)
        for _ in range(MAX_STEPS):
            call = self._parse_call(text)
            if not call:
                break
            name, args = call

            # (2) Execute whatever tool the model asks for -- no allow-list,
            #     no argument validation, no confirmation on destructive calls.
            tool = getattr(self.sandbox, name, None)
            if tool is None:
                break

            # Naive convenience: splice a previously read file into an arg.
            args = [last_read if a == "{file}" else a for a in args]
            result = tool(*args)
            if name == "read_file":
                last_read = str(result)

            # (3) Feed tool output straight back into the model context -- this is
            #     the indirect-injection channel (e.g. a fetched web page whose
            #     text contains its own TOOL: directives).
            context = f"{context}\nTOOL_RESULT: {result}"
            text = self.model.complete(self.SYSTEM, context)

        # (4) Return raw model text -- secrets and system prompt included.
        return AgentResponse(text=text, sandbox=self.sandbox)

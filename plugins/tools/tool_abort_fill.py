"""abort_fill — the escape hatch offered during a forced parameter fill.

A parameter-fill model call is *forced* (tool_choice requires a call), so the
model cannot decline by replying with text. Without an out, a model that
realizes mid-fill that the selected tool is wrong would be pushed into emitting
confident garbage — the worst failure mode. ``abort_fill`` is the out: calling
it cleanly abandons the selection with a reason and bounces the agent back to
``search_tools`` on the next turn.

This tool is never shown on a normal turn — only the ConversationLoop injects it
alongside the target during a fill (``_prepare_fill_call``). Aborts flow through
the normal call_tool/ledger path, so the fill-abort rate is readable straight
off the action ledger (a usefulness signal for catalog eviction).
"""

from __future__ import annotations

from plugins.BaseTool import BaseTool, ToolResult


class AbortFill(BaseTool):
    """Abandon a parameter fill when the selected tool is wrong."""

    name = "abort_fill"
    description = (
        "Abort filling the selected tool's parameters because it is the wrong "
        "tool or the task can't be done with it. Give a brief reason; you'll be "
        "returned to search_tools."
    )
    parameters = {
        "type": "object",
        "properties": {
            "reason": {
                "type": "string",
                "description": "Brief reason the selected tool is wrong or unusable.",
            },
        },
        "required": ["reason"],
    }
    max_calls = 20
    background_safe = True

    def run(self, context, **kwargs) -> ToolResult:
        """Record the abort and steer the agent back to search."""
        reason = (kwargs.get("reason") or "").strip() or "no reason given"
        return ToolResult(
            success=True,
            llm_summary=(
                f"Aborted parameter fill: {reason}. Use search_tools to find a "
                "more suitable tool, or answer the user directly if none fits."
            ),
            data={"aborted": True, "reason": reason},
        )

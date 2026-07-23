"""execute_tool — the agent's execution half of the two-tool interface.

The agent selects a tool by name (found via ``search_tools``) and states its
intent — a one-sentence *why* that carries across the decision→fill boundary.
This tool does not run the target directly; it **selects** it. The selection is
parked on ``session.pending_fill`` and the ConversationLoop shapes a separate,
forced parameter-fill model call (see ``_prepare_fill_call``), presenting only
the chosen tool's schema plus ``abort_fill``. Splitting the decision (which
tool + why) from the fill (with what arguments) keeps each model call fully
on-distribution: a normal tool call, just forced.
"""

from __future__ import annotations

from plugins.BaseTool import BaseTool, ToolResult

_KERNEL_TOOLS = {"search_tools", "execute_tool", "abort_fill"}


class ExecuteTool(BaseTool):
    """Select a catalog tool to run, by name and intent."""

    name = "execute_tool"
    description = (
        "Select a tool to run, by name (from search_tools) plus a one-sentence "
        "intent describing why you're using it. You will then be prompted to "
        "fill in that tool's parameters. Use this for every capability beyond "
        "search_tools itself."
    )
    parameters = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "The exact tool name to run, as returned by search_tools.",
            },
            "intent": {
                "type": "string",
                "description": "One sentence: what you're trying to accomplish with this tool right now.",
            },
        },
        "required": ["name", "intent"],
    }
    max_calls = 20
    background_safe = True

    def run(self, context, **kwargs) -> ToolResult:
        """Validate the chosen tool exists and park the selection for fill."""
        name = (kwargs.get("name") or "").strip()
        intent = (kwargs.get("intent") or "").strip()
        if not name:
            return ToolResult.failed("execute_tool needs a tool name (find one with search_tools).")

        registry = context.tool_registry
        tools = (getattr(registry, "tools", {}) or {}) if registry else {}
        if name in _KERNEL_TOOLS:
            return ToolResult.failed(
                f"'{name}' is part of the tool interface and can't be executed directly."
            )
        if name not in tools:
            return ToolResult.failed(
                f"Unknown tool '{name}'. Use search_tools to find an available tool by description."
            )

        # Park the selection; the ConversationLoop drains it into a forced
        # parameter-fill call at the next loop boundary. Requires a live session.
        session = None
        runtime = context.runtime
        if runtime is not None and context.session_key:
            session = (getattr(runtime, "sessions", {}) or {}).get(context.session_key)
        if session is None:
            return ToolResult.failed(
                "execute_tool needs an interactive session to fill parameters; "
                "it can't be used from this context."
            )
        with session.lock:
            session.pending_fill = {"name": name, "intent": intent}

        return ToolResult(
            success=True,
            llm_summary=f"Selected '{name}'. Now fill in its parameters.",
            data={"selected": name, "intent": intent},
        )

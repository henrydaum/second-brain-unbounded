"""Slash command plugin for `/tools`."""

from plugins.BaseCommand import BaseCommand

ACTIONS = ["call", "toggle_skip_permissions"]
ACTION_LABELS = ["Call tool", "Toggle skip permissions"]


class ToolsCommand(BaseCommand):
    """Slash-command handler for `/tools`.

    The first real user of ``CallTool``, and the reason that verb cannot carry a
    fixed tier: ``/tools call`` can invoke *anything* in the catalog. Grading the
    wrapper would mean either gating a call to a read-only search tool as though
    it were a shell, or letting a shell call through as though it were a search.
    So the tier is borrowed from the target, and the human sees an approval
    exactly when the tool they picked would have needed one.

    ``skip_permissions`` is user-scoped, so its write goes through
    ``WriteConfig(scope="user")`` — the setting lives on the user's config blob
    rather than the global file, and that distinction is now carried by the
    request instead of by the plugin remembering which writer to call.
    """
    name = "tools"
    description = "Select a tool, then call it"
    category = "System"

    contract = "effects"
    declared_requests = ["read_context", "call_tool", "read_config", "write_config"]

    def form(self, params):
        """Offer the tool list, then its actions, then the tool's own arguments."""
        tools = yield from _tools()
        steps = [{"name": "tool_name", "prompt": "Select a tool to inspect or call.",
                  "required": True, "columns": 2,
                  "enum": sorted(t["name"] for t in tools)}]

        chosen = _find(tools, params.get("tool_name"))
        if chosen:
            skipped = yield from _is_skipped(chosen["name"])
            steps.append({"name": "action", "required": True,
                          "prompt": ("What do you want to do with this tool?\n\n"
                                     f"{_card(chosen, skipped)}"),
                          "enum": ACTIONS, "enum_labels": ACTION_LABELS})

        if chosen and params.get("action") == "call":
            steps += _argument_steps(chosen)
        return steps

    def run(self, params):
        """Execute `/tools` for the active session."""
        from effects.vocabulary import CallTool, Respond, WriteConfig

        tools = yield from _tools()
        name = params.get("tool_name")
        if not name:
            return Respond(data=_listing(tools))

        tool = _find(tools, name)
        if tool is None:
            return Respond(data="Unknown tool.")

        action = params.get("action")
        if not action:
            skipped = yield from _is_skipped(name)
            return Respond(data=_card(tool, skipped))

        if action == "call":
            arguments = {key: params[key] for key in _argument_names(tool) if key in params}
            result = yield CallTool(name=name, params=arguments)
            if not result.ok:
                return Respond(data=f"Tool call failed: {result.error}")
            return Respond(data=_format_result(result.value or {}))

        if action == "toggle_skip_permissions":
            current = yield from _skip_list()
            turning_on = name not in current
            current.add(name) if turning_on else current.discard(name)

            written = yield WriteConfig(key="skip_permissions",
                                        value=sorted(current), scope="user")
            if not written.ok:
                return Respond(data=f"Could not update skip permissions: {written.error}")
            return Respond(data=(f"Skip permissions {'enabled' if turning_on else 'disabled'} "
                                 f"for {name}."))

        return Respond(data=f"Unknown action: {action}")


def _tools():
    """Yield the tools inventory."""
    from effects.vocabulary import ReadContext

    result = yield ReadContext(view="tools")
    return result.value or []


def _skip_list():
    """Yield the user's skip_permissions set."""
    from effects.vocabulary import ReadConfig

    result = yield ReadConfig(key="skip_permissions", scope="user")
    return {str(n) for n in (result.value or []) if str(n)}


def _is_skipped(name: str):
    """Whether *name* is on the user's skip_permissions list."""
    current = yield from _skip_list()
    return name in current


def _find(tools, name):
    """One tool's inventory entry, or None."""
    return next((t for t in tools if t["name"] == name), None) if name else None


def _parameters(tool) -> dict:
    """The tool's JSON-schema parameter block."""
    return (tool.get("parameters") or {}).get("properties") or {}


def _argument_names(tool) -> list[str]:
    """Names of the tool's declared arguments."""
    return list(_parameters(tool))


def _argument_steps(tool) -> list[dict]:
    """Form steps for the chosen tool's own arguments.

    Built from the schema rather than by calling the tool's ``to_schema`` — the
    inventory already carries it as data, so the command never holds the tool."""
    required = set((tool.get("parameters") or {}).get("required") or [])
    steps = []
    for name, spec in _parameters(tool).items():
        step = {"name": name, "required": name in required,
                "prompt": spec.get("description") or name,
                "prompt_when_missing": True}
        if spec.get("type") in ("array", "boolean", "integer", "number"):
            step["type"] = spec["type"]
        if spec.get("enum"):
            step["enum"] = list(spec["enum"])
        steps.append(step)
    return steps


def _listing(tools) -> str:
    """The tool catalog table."""
    import sandbox_kit as kit

    if not tools:
        return "No tools are registered."
    rows = [(t["name"], t.get("danger_tier") or "-",
             ", ".join(_argument_names(t)) or "(none)",
             kit.truncate_chars(t.get("description") or "", 80)[0])
            for t in tools]
    return "Tools:\n\n" + kit.md_table(["Tool", "Tier", "Args", "Description"], rows)


def _card(tool, skipped: bool) -> str:
    """A describe card for one tool."""
    import sandbox_kit as kit

    required = set((tool.get("parameters") or {}).get("required") or [])
    fields = [f"{name}{'*' if name in required else ''}" for name in _parameters(tool)]
    pairs = [("Args", ", ".join(fields) or "(none)"),
             ("Danger tier", tool.get("danger_tier") or "-"),
             ("Contract", tool.get("contract") or "legacy"),
             ("Skip permissions", "enabled" if skipped else "disabled")]
    if tool.get("declared_requests"):
        pairs.append(("Requests", ", ".join(tool["declared_requests"])))

    card = kit.detail_card(tool["name"], pairs)
    description = (tool.get("description") or "").strip()
    return f"{card}\n\n{kit.quote_block(description)}" if description else card


def _format_result(result: dict) -> str:
    """Render a tool result the way /tools always has."""
    import sandbox_kit as kit

    parts = []
    if result.get("summary"):
        parts.append(str(result["summary"]))
    if not result.get("success", True) and result.get("error"):
        parts.append(f"Error: {result['error']}")
    data = result.get("data")
    if data not in (None, "", [], {}):
        parts.append(kit.quote_block(str(data)[:2000]))
    return "\n\n".join(parts) or "(no output)"

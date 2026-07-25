"""Slash command plugin for `/commands`."""

from plugins.BaseCommand import BaseCommand

_HELP_SECTIONS = ["Conversation", "System", "Services & Tools", "Tasks", "Config & System", "Other"]


class CommandsCommand(BaseCommand):
    """Slash-command handler for `/commands`.

    Was: reach into ``context.command_registry`` and call ``help_text``, handing
    the plugin a live registry and a live predicate. Now the kernel returns the
    command list as data (already filtered by the session's frontend policy) and
    the formatting happens here, which is where it belonged — it is pure string
    work over a list of dicts.
    """
    name = "commands"
    description = "List available commands"
    category = "Conversation"

    contract = "effects"
    declared_requests = ["read_context"]

    def run(self, _params):
        """Execute `/commands` for the active session."""
        from effects.vocabulary import ReadContext, Respond
        from plugins.frontends.helpers.formatters import md_table

        result = yield ReadContext(view="commands")
        if not result.ok:
            return Respond(data="No command registry is available.")
        commands = result.value or []
        if not commands:
            return Respond(data="No commands are available.")

        by_cat: dict[str, list[dict]] = {}
        for entry in commands:
            by_cat.setdefault(entry.get("category") or "Other", []).append(entry)
        ordered = ([c for c in _HELP_SECTIONS if c in by_cat]
                   + [c for c in by_cat if c not in _HELP_SECTIONS])

        lines = ["Commands:"]
        for category in ordered:
            rows = []
            for entry in by_cat[category]:
                hint = entry.get("arg_hint") or ""
                label = "/" + entry["name"] + ((" " + hint) if hint else "")
                rows.append((label, entry.get("description") or ""))
            # The blank line before the table matters: without it, markdown
            # parsers fold the table into the heading's paragraph.
            lines += ["", f"**{category}**", "", md_table(["Command", "Description"], rows)]
        return Respond(data="\n".join(lines))

"""Slash command plugin for `/frontends`."""

from plugins.BaseCommand import BaseCommand

ACTIONS = ["configure", "enable", "disable"]
ACTION_LABELS = ["Edit", "Enable", "Disable"]

# Editable fields of a frontend profile. Each profile pins the agent profile
# used by sessions on that frontend and narrows which slash commands the user
# may run there.
FIELDS = ["agent_profile", "whitelist_or_blacklist_commands", "commands_list"]
FIELD_LABELS = ["Agent profile", "Command mode", "Command list"]
DEFAULT_PROFILE = {
    "agent_profile": "default",
    "whitelist_or_blacklist_commands": "blacklist",
    "commands_list": [],
}


class FrontendsCommand(BaseCommand):
    """Slash-command handler for `/frontends`.

    Note what this command edits: ``frontend_profiles`` decides which slash
    commands are reachable on a frontend and which agent profile its sessions
    use. It is access policy, so it is exactly the kind of config an agent must
    not be able to rewrite quietly — and with the write going through
    ``WriteConfig``, it now cannot. The human typing ``/frontends`` is the
    ``allow`` corner; anything else is gated or refused.
    """
    name = "frontends"
    description = "Enable/disable a frontend or configure its access profile"
    category = "System"

    contract = "effects"
    declared_requests = ["read_context", "write_config"]

    def form(self, params):
        """Offer the frontend list, its actions, and the profile-field editor."""
        frontends = yield from _view("frontends")
        steps = [{"name": "frontend_name", "prompt": "Select a frontend.",
                  "required": True, "columns": 2,
                  "enum": [f["name"] for f in frontends]}]

        chosen = _find(frontends, params.get("frontend_name"))
        if chosen:
            steps.append({"name": "action", "required": True,
                          "prompt": ("What do you want to do with this frontend?"
                                     f"\n\n{_card(chosen)}"),
                          "enum": ACTIONS, "enum_labels": ACTION_LABELS})

        if params.get("action") == "configure":
            steps.append({"name": "field", "required": True,
                          "prompt": "Choose which part of the frontend profile to edit.",
                          "enum": FIELDS, "enum_labels": FIELD_LABELS})
            field = params.get("field")
            if field:
                steps.append((yield from _value_step(field)))
        return steps

    def run(self, params):
        """Execute `/frontends` for the active session."""
        from effects.vocabulary import Respond

        frontends = yield from _view("frontends")
        name = params.get("frontend_name")
        if not name:
            return Respond(data=_listing(frontends))

        action = params.get("action")
        if action in ("enable", "disable"):
            return (yield from _toggle(frontends, name, action))
        if action == "configure":
            return (yield from _configure(frontends, name, params.get("field"),
                                          params.get("value")))
        return Respond(data=f"Unknown action: {action}")


def _view(name: str):
    """Yield one inventory view."""
    from effects.vocabulary import ReadContext

    result = yield ReadContext(view=name)
    return result.value or []


def _find(entries, name):
    """One inventory entry by name, or None."""
    return next((e for e in entries if e["name"] == name), None) if name else None


def _toggle(frontends, name: str, action: str):
    """Enable or disable a frontend. The frontend itself starts on restart."""
    from effects.vocabulary import Respond, WriteConfig

    enabled = {f["name"] for f in frontends if f["enabled"]}
    if action == "disable" and enabled == {name}:
        return Respond(data="Cannot disable the last enabled frontend.")
    enabled.add(name) if action == "enable" else enabled.discard(name)

    result = yield WriteConfig(key="enabled_frontends", value=sorted(enabled))
    if not result.ok:
        return Respond(data=f"Could not update frontends: {result.error}")
    return Respond(data=(f"{'Enabled' if action == 'enable' else 'Disabled'} "
                         f"frontend: {name}. Restart required."))


def _configure(frontends, name: str, field: str, value):
    """Write one frontend-profile field. Takes effect on the next turn."""
    from effects.vocabulary import Respond, WriteConfig

    if field not in FIELDS:
        return Respond(data=f"Unknown field: {field}")
    if field == "whitelist_or_blacklist_commands" and value not in ("whitelist", "blacklist"):
        return Respond(data="Command mode must be 'whitelist' or 'blacklist'.")

    profiles = {f["name"]: dict(f.get("profile") or {}) for f in frontends
                if f.get("profile")}
    profile = profiles.setdefault(name, dict(DEFAULT_PROFILE))
    profile[field] = _coerce(field, value)

    result = yield WriteConfig(key="frontend_profiles", value=profiles)
    if not result.ok:
        return Respond(data=f"Could not update the profile: {result.error}")

    note = ""
    if field == "whitelist_or_blacklist_commands" and value == "whitelist" \
            and not profile.get("commands_list"):
        note = "\nNote: whitelist is empty — every command is now blocked on this frontend."
    label = FIELD_LABELS[FIELDS.index(field)]
    return Respond(data=f"Updated {name} profile: {label} → {_render(field, profile[field])}{note}")


def _coerce(field: str, value):
    """Normalise a submitted profile value to its stored shape."""
    import json

    if field == "commands_list":
        if isinstance(value, list):
            return value
        try:
            return json.loads(value or "[]")
        except (TypeError, ValueError):
            # A comma-separated list is what a human actually types.
            return [part.strip() for part in str(value or "").split(",") if part.strip()]
    return "" if value is None else str(value)


def _value_step(field: str):
    """The value step for the chosen profile field."""
    if field == "agent_profile":
        return {"name": "value", "required": True, "default": "default",
                "enum": ["default"],
                "prompt": ("Choose the agent profile sessions on this frontend should "
                           "use. 'default' follows the global active profile.")}
    if field == "whitelist_or_blacklist_commands":
        return {"name": "value", "required": True, "default": "blacklist",
                "enum": ["blacklist", "whitelist"],
                "enum_labels": ["Blacklist commands", "Whitelist commands"],
                "prompt": ("Blacklist blocks the listed commands; whitelist allows "
                           "only the listed commands.")}
    commands = yield from _view("commands")
    names = ", ".join(sorted(c["name"] for c in commands)) or "(none)"
    return {"name": "value", "required": False, "type": "array", "default": [],
            "prompt_when_missing": True,
            "prompt": f"Command names for the list. Available: {names}"}


def _listing(frontends) -> str:
    """The frontend table."""
    import sandbox_kit as kit

    rows = [(f["name"], "Enabled" if f["enabled"] else "Disabled",
             _profile_summary(f.get("profile")))
            for f in frontends]
    return "Frontends:\n\n" + kit.md_table(["Frontend", "Status", "Access"], rows)


def _card(frontend) -> str:
    """A describe card for one frontend."""
    import sandbox_kit as kit

    return kit.detail_card(frontend["name"], [
        ("Status", "Enabled" if frontend["enabled"] else "Disabled"),
        ("Running", "yes" if frontend.get("running") else "no"),
        ("Profile", _profile_summary(frontend.get("profile"))),
    ])


def _profile_summary(profile) -> str:
    """One-line description of a profile, or the unrestricted default."""
    if not profile:
        return "agent default, all commands"
    agent = profile.get("agent_profile") or "default"
    mode = profile.get("whitelist_or_blacklist_commands", "blacklist")
    listed = profile.get("commands_list") or []
    if listed:
        commands = f"{mode} {', '.join(listed)}"
    else:
        commands = "whitelist (none → all blocked)" if mode == "whitelist" else "all commands"
    return f"agent {agent}, {commands}"


def _render(field: str, value) -> str:
    """Format a saved value for the confirmation message."""
    if field == "commands_list":
        return ", ".join(value) or "(none)"
    return str(value)

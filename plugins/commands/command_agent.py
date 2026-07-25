"""Slash command plugin for `/agent`."""

from plugins.BaseCommand import BaseCommand

ACTIONS = ["switch", "edit", "remove"]
ACTION_LABELS = ["Switch to it", "Edit it", "Remove it"]
PROFILE_FIELDS = ["llm", "prompt_suffix", "whitelist_or_blacklist_tools", "tools_list"]
FIELDS = ["agent_profile_name", *PROFILE_FIELDS]
FIELD_LABELS = ["Profile name", "LLM", "Prompt suffix", "Tool mode", "Tool list"]


class AgentCommand(BaseCommand):
    """Slash-command handler for `/agent`.

    Note the two scopes in play, which the requests now carry explicitly:
    ``agent_profiles`` is global (the definitions are shared), while
    ``active_agent_profile`` is **user-scoped** (which one you selected is yours).
    The imperative version encoded that by choosing between
    ``runtime.set_user_setting`` and ``config_manager.save`` at three different
    call sites; here it is one ``scope=`` argument.

    A profile is also access policy — ``tools_list`` narrows what the agent can
    reach — so an agent rewriting one is exactly what the principal gate refuses.
    """
    name = "agent"
    description = "Select an agent profile, then switch, edit, or remove it"
    category = "System"
    agent_prompt = (
        "Agent profiles can be switched mid-conversation with /agent, changing "
        "the LLM, tool access, and extra instructions from that point on. The "
        "[SYSTEM CONTEXT UPDATE] block names the profile active for the "
        "current turn."
    )

    contract = "effects"
    declared_requests = ["read_context", "read_config", "write_config", "session_action"]

    def form(self, params):
        """Offer the profile list, then the action, then the edit fields."""
        profiles = yield from _profiles()
        active = yield from _active()
        names = [*sorted(profiles), "add"]
        steps = [{"name": "profile_name", "required": True,
                  "prompt": "Select an agent profile, or add a new one.",
                  "enum": names,
                  "enum_labels": [_label(n, active) for n in names]}]

        chosen = params.get("profile_name")
        if chosen == "add":
            llms = yield from _llm_names()
            tools = yield from _tool_names()
            return steps + _add_steps(llms, tools)

        if chosen:
            steps.append({"name": "action", "required": True,
                          "prompt": ("What do you want to do with this agent profile?"
                                     f"\n\n{_card(chosen, profiles.get(chosen), active)}"),
                          "enum": ACTIONS, "enum_labels": ACTION_LABELS})
        if params.get("action") == "edit":
            field = params.get("field")
            steps += [{"name": "field", "required": True, "enum": FIELDS,
                       "enum_labels": FIELD_LABELS,
                       "prompt": "Choose which part of the agent profile to edit."},
                      {"name": "value", "required": True,
                       "type": "array" if field == "tools_list" else "string",
                       "prompt": _value_prompt(field)}]
        return steps

    def run(self, params):
        """Execute `/agent` for the active session."""
        from effects.vocabulary import Respond, SessionAction, WriteConfig

        profiles = yield from _profiles()
        name = params.get("profile_name")

        if name == "add":
            name = (params.get("new_profile_name") or "").strip()
            if not name:
                return Respond(data="Profile name is required.")
            profiles[name] = {field: _coerce(field, params.get(field))
                              for field in PROFILE_FIELDS}
            written = yield WriteConfig(key="agent_profiles", value=profiles)
            if not written.ok:
                return Respond(data=f"Could not add the profile: {written.error}")
            return Respond(data=f"Added agent profile: {name}")

        if name not in profiles:
            return Respond(data="Unknown agent profile.")
        action = params.get("action")

        if action == "switch":
            switched = yield SessionAction(action="set_agent_profile", payload={"name": name})
            yield WriteConfig(key="active_agent_profile", value=name, scope="user")
            verb = "Switched agent profile to" if (switched.value or {}).get("ok") \
                else "Active agent profile set to"
            return Respond(data=f"{verb}: {name}")

        if action == "edit":
            return (yield from _edit(profiles, name, params))

        if action == "remove":
            if name == "default":
                return Respond(data="Cannot remove the default agent profile.")
            profiles.pop(name, None)
            written = yield WriteConfig(key="agent_profiles", value=profiles)
            if not written.ok:
                return Respond(data=f"Could not remove the profile: {written.error}")
            if (yield from _active()) == name:
                yield WriteConfig(key="active_agent_profile", value="default", scope="user")
            yield SessionAction(action="refresh_specs")
            return Respond(data=f"Removed agent profile: {name}")

        return Respond(data=f"Unknown action: {action}")


def _edit(profiles: dict, name: str, params: dict):
    """Apply one field edit, renaming the profile when the field is its name."""
    from effects.vocabulary import Respond, SessionAction, WriteConfig

    field = params.get("field")
    if field not in FIELDS:
        return Respond(data=f"Unknown field: {field}")

    if field == "agent_profile_name":
        new_name = _coerce(field, params.get("value")).strip()
        if not new_name:
            return Respond(data="Profile name is required.")
        if new_name != name and new_name in profiles:
            return Respond(data=f"Agent profile already exists: {new_name}")
        profiles[new_name] = profiles.pop(name)
        renamed, name = True, new_name
    else:
        profiles.setdefault(name, {})[field] = _coerce(field, params.get("value"))
        renamed = False

    written = yield WriteConfig(key="agent_profiles", value=profiles)
    if not written.ok:
        return Respond(data=f"Could not update the profile: {written.error}")

    if renamed:
        old = params.get("profile_name")
        if (yield from _active()) == old:
            yield WriteConfig(key="active_agent_profile", value=name, scope="user")
        # Live sessions hold the name by value; the kernel fixes the stale refs.
        yield SessionAction(action="rename_agent_profile",
                            payload={"old": old, "new": name})
    else:
        yield SessionAction(action="refresh_specs")
    return Respond(data=f"Updated agent profile: {name}")


def _profiles():
    """Yield the global agent-profile definitions."""
    from effects.vocabulary import ReadConfig

    result = yield ReadConfig(key="agent_profiles")
    return dict(result.value or {})


def _active():
    """Yield the current user's selected profile."""
    from effects.vocabulary import ReadConfig

    result = yield ReadConfig(key="active_agent_profile", scope="user")
    return result.value


def _llm_names():
    """Yield the configured LLM profile names, 'default' first."""
    from effects.vocabulary import ReadConfig

    result = yield ReadConfig(key="llm_profiles")
    return ["default", *sorted(result.value or {})]


def _tool_names():
    """Yield the registered tool names."""
    from effects.vocabulary import ReadContext

    result = yield ReadContext(view="tools")
    return sorted(tool["name"] for tool in (result.value or []))


def _add_steps(llms: list[str], tools: list[str]) -> list[dict]:
    """The new-profile form."""
    return [
        {"name": "new_profile_name", "required": True,
         "prompt": "Enter a short name for the new agent profile."},
        {"name": "llm", "required": True, "enum": llms, "default": "default",
         "prompt": ("Choose the LLM this agent should use. Select default to "
                    "follow the current default LLM.")},
        {"name": "prompt_suffix", "required": False, "default": "",
         "prompt_when_missing": True,
         "prompt": "Optional extra instructions to append to this agent's system prompt."},
        {"name": "whitelist_or_blacklist_tools", "required": True,
         "enum": ["blacklist", "whitelist"], "default": "blacklist",
         "enum_labels": ["Blacklist tools", "Whitelist tools"],
         "prompt": "Choose how this profile should treat the tool list."},
        {"name": "tools_list", "required": False, "type": "array", "default": [],
         "prompt_when_missing": True,
         "prompt": f"Optional tool names. Available: {', '.join(tools) or '(none)'}"},
    ]


def _coerce(field: str, value):
    """Normalise a submitted field value to its stored shape."""
    import json

    if field == "tools_list":
        if isinstance(value, list):
            return value
        try:
            return json.loads(value or "[]")
        except (TypeError, ValueError):
            return [part.strip() for part in str(value or "").split(",") if part.strip()]
    return "" if value is None else str(value)


def _card(name: str, profile: dict | None, active) -> str:
    """A describe card for one agent profile."""
    import sandbox_kit as kit

    if not profile:
        return "Action"
    suffix = " (active)" if active == name else ""
    return kit.detail_card(f"{name}{suffix}", [
        ("LLM", profile.get("llm", "default")),
        ("Tool mode", profile.get("whitelist_or_blacklist_tools", "blacklist")),
        ("Tool list", ", ".join(profile.get("tools_list") or []) or "(none)"),
    ])


def _label(name: str, active) -> str:
    """Menu label for a profile name."""
    if name == "add":
        return "Add profile"
    return f"{name} (active)" if active == name else name


def _value_prompt(field) -> str:
    """The prompt for the chosen edit field."""
    return {
        "agent_profile_name": "Enter the new profile name.",
        "llm": "Enter the LLM profile name, or default.",
        "prompt_suffix": "Enter the extra system-prompt instructions for this agent.",
        "whitelist_or_blacklist_tools": ("Enter blacklist to block listed tools, or "
                                         "whitelist to allow only listed tools."),
        "tools_list": "Enter tool names.",
    }.get(field, "Enter the new value.")

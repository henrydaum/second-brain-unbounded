"""Slash command plugin for `/llm`."""

from plugins.BaseCommand import BaseCommand

ACTIONS = ["edit", "set_default", "remove"]
ACTION_LABELS = ["Edit", "Set default", "Remove"]
PROFILE_FIELDS = ["llm_endpoint", "llm_api_key", "llm_context_size", "llm_service_class",
                  "llm_capability_image", "llm_capability_audio", "llm_capability_video"]
FIELDS = ["llm_model_name", *PROFILE_FIELDS]
FIELD_LABELS = ["Model name", "Endpoint", "API key", "Context size", "Service class",
                "Images", "Audio", "Video"]
DEFAULT_BACKEND = "LiteLLMService"
CAPABILITY_FIELDS = {
    "llm_capability_image": "image",
    "llm_capability_audio": "audio",
    "llm_capability_video": "video",
}


class LlmCommand(BaseCommand):
    """Slash-command handler for `/llm`.

    The command that most obviously should not be reachable by an agent: it sets
    which model the system talks to and what API key that call carries. It is
    also the one whose old shape most clearly needed inverting — it reached into
    the live router with ``add_llm``/``remove_llm`` after every edit, so the
    plugin was responsible for keeping the kernel's derived state consistent.

    Now the plugin only writes config. The kernel notices that ``llm_profiles``
    or ``default_llm_profile`` changed and resyncs the router itself, exactly as
    it rescans the file watcher when the sync directories change. A plugin that
    has to remember to refresh something eventually forgets.

    Note the API key still passes through this body on its way into config. That
    is the irreducible case from PRIMITIVES.md, and it is why ``/llm`` stays a
    built-in: the value has to reach the kernel somehow, and a human typing it
    into their own machine's config is the one path where that is fine.
    """
    name = "llm"
    description = "Select an LLM profile, then edit, set default, or remove it"
    category = "System"
    agent_prompt = (
        "The default LLM can be switched mid-conversation with /llm. Earlier "
        "assistant turns in this conversation may have been produced by a "
        "different model; the [SYSTEM CONTEXT UPDATE] block names the model "
        "driving the current turn. A changed model is normal, not manipulation."
    )

    contract = "effects"
    declared_requests = ["read_context", "read_config", "write_config"]

    def form(self, params):
        """Offer the profile list, then add-fields or the action/edit steps."""
        profiles, default = yield from _state()
        names = [*sorted(profiles), "add"]
        steps = [{"name": "model_name", "required": True, "enum": names,
                  "enum_labels": [_label(n, default) for n in names],
                  "prompt": ("Select an LLM profile, or add a new one.\n"
                             f"Default: {default or '(none)'}")}]

        if params.get("model_name") == "add":
            backends = yield from _backends()
            return steps + _add_steps(backends)

        chosen = params.get("model_name")
        if chosen:
            steps.append({"name": "action", "required": True, "enum": ACTIONS,
                          "enum_labels": ACTION_LABELS,
                          "prompt": ("What do you want to do with this LLM profile?"
                                     f"\n\n{_card(chosen, profiles.get(chosen), default)}")})
        if params.get("action") == "edit":
            backends = yield from _backends()
            field = params.get("field")
            steps += [{"name": "field", "required": True, "enum": FIELDS,
                       "enum_labels": FIELD_LABELS,
                       "prompt": "Choose which LLM setting to edit."},
                      {"name": "value", "required": True, "type": _value_type(field),
                       "prompt": _value_prompt(field, backends)}]
        return steps

    def run(self, params):
        """Execute `/llm` for the active session."""
        from effects.vocabulary import Respond

        profiles, default = yield from _state()
        name = params.get("model_name")

        if name == "add":
            new_name = (params.get("new_model_name") or "").strip()
            if not new_name:
                return Respond(data="Model name is required.")
            first_profile = not profiles
            profiles[new_name] = _profile(params)
            if err := (yield from _save_profiles(profiles)):
                return Respond(data=err)
            if first_profile:
                # The first profile added becomes the default; later ones do not
                # displace a working choice.
                yield from _save_default(new_name)
            return Respond(data=f"Added LLM profile: {new_name}")

        if name not in profiles:
            return Respond(data="Unknown LLM profile.")
        action = params.get("action")

        if action == "edit":
            return (yield from _edit(profiles, default, name, params))

        if action == "set_default":
            if err := (yield from _save_default(name)):
                return Respond(data=err)
            return Respond(data=f"Default LLM profile set to: {name}")

        if action == "remove":
            ordered = sorted(profiles)
            profiles.pop(name, None)
            if err := (yield from _save_profiles(profiles)):
                return Respond(data=err)
            if default == name:
                # Fall to the neighbour that took this one's place in the
                # ordering, so removing the default never leaves nothing selected
                # while other profiles remain.
                remaining = [n for n in ordered if n != name]
                replacement = (remaining[min(ordered.index(name), len(remaining) - 1)]
                               if remaining else "")
                yield from _save_default(replacement)
            return Respond(data=f"Removed LLM profile: {name}")

        return Respond(data=f"Unknown action: {action}")


def _edit(profiles: dict, default: str, name: str, params: dict):
    """Apply one field edit, renaming the profile when the field is its name."""
    from effects.vocabulary import Respond

    field = params.get("field")
    if field not in FIELDS:
        return Respond(data=f"Unknown field: {field}")

    if field == "llm_model_name":
        new_name = _coerce(field, params.get("value")).strip()
        if not new_name:
            return Respond(data="Model name is required.")
        if new_name != name and new_name in profiles:
            return Respond(data=f"LLM profile already exists: {new_name}")
        profiles[new_name] = profiles.pop(name)
        renamed, name = name, new_name
    elif field in CAPABILITY_FIELDS:
        capabilities = profiles[name].setdefault("llm_capabilities", {})
        capabilities[CAPABILITY_FIELDS[field]] = _coerce(field, params.get("value"))
        renamed = None
    else:
        profiles[name][field] = _coerce(field, params.get("value"))
        renamed = None

    if err := (yield from _save_profiles(profiles)):
        return Respond(data=err)
    if renamed and default == renamed:
        yield from _save_default(name)
    return Respond(data=f"Updated LLM profile: {name}")


def _state():
    """Yield the profile map and the current default's name."""
    from effects.vocabulary import ReadConfig

    result = yield ReadConfig(keys=["llm_profiles", "default_llm_profile"])
    values = result.value or {}
    return dict(values.get("llm_profiles") or {}), (values.get("default_llm_profile") or "")


def _backends():
    """Yield the installed LLM backend class names."""
    from effects.vocabulary import ReadContext

    result = yield ReadContext(view="llm_backends")
    return list(result.value or []) or [DEFAULT_BACKEND]


def _save_profiles(profiles: dict) -> str:
    """Persist the profile map. Returns an error message, or '' on success.

    Writing this key is also what resyncs the live router — the kernel owns that
    derived state, so the plugin does not touch it."""
    from effects.vocabulary import WriteConfig

    # scope="plugin": these keys belong to service_llm's config file, and saying
    # so is more robust than relying on discovery to classify them.
    result = yield WriteConfig(key="llm_profiles", value=profiles, scope="plugin")
    return "" if result.ok else f"Could not save LLM profiles: {result.error}"


def _save_default(name: str) -> str:
    """Persist the default profile name. Returns an error message, or ''."""
    from effects.vocabulary import WriteConfig

    result = yield WriteConfig(key="default_llm_profile", value=name, scope="plugin")
    return "" if result.ok else f"Could not set the default LLM: {result.error}"


def _profile(params: dict) -> dict:
    """Build a profile dict from the add-form answers."""
    profile = {field: _coerce(field, params.get(field))
               for field in PROFILE_FIELDS if field not in CAPABILITY_FIELDS}
    capabilities = {cap: _coerce(field, params.get(field))
                    for field, cap in CAPABILITY_FIELDS.items()
                    if params.get(field) is not None}
    if capabilities:
        profile["llm_capabilities"] = capabilities
    return profile


def _coerce(field: str, value):
    """Normalise one submitted field value."""
    if field == "llm_context_size":
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0
    if field in CAPABILITY_FIELDS:
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"true", "yes", "1", "y"}
    return "" if value is None else str(value)


def _value_type(field) -> str:
    """The form type for an edit value."""
    if field == "llm_context_size":
        return "integer"
    return "boolean" if field in CAPABILITY_FIELDS else "string"


def _add_steps(backends: list[str]) -> list[dict]:
    """The new-profile form."""
    return [
        {"name": "llm_service_class", "required": True, "enum": backends,
         "default": backends[0],
         "prompt": "Choose how Second Brain should connect to this model."},
        {"name": "new_model_name", "required": True,
         "prompt": ("Enter the model name exactly, including provider prefix when "
                    "needed (for example `openai/gpt-4o-mini` or "
                    "`anthropic/claude-3-5-sonnet-latest`).")},
        {"name": "llm_endpoint", "required": False, "default": "",
         "prompt_when_missing": True,
         "prompt": ("Enter the provider base URL [optional]. Leave blank for the "
                    "provider default.")},
        {"name": "llm_api_key", "required": False, "default": "",
         "prompt_when_missing": True,
         "prompt": ("Enter the API key, or the environment variable name that "
                    "contains it. Leave blank to use the provider default.")},
        {"name": "llm_context_size", "required": False, "type": "integer", "default": 0,
         "prompt_when_missing": True,
         "prompt": ("Optional context window size in tokens. Use 0 for dynamic "
                    "compaction or if unknown.")},
        *[{"name": field, "required": False, "type": "boolean", "default": None,
           "prompt_when_missing": True,
           "prompt": (f"Can this model read {cap} natively? "
                      "Choose yes/no, or /skip if unsure.")}
          for field, cap in CAPABILITY_FIELDS.items()],
    ]


def _card(name: str, profile: dict | None, default: str) -> str:
    """A describe card for one LLM profile."""
    import sandbox_kit as kit

    if not profile:
        return "Action"
    mark = " (default)" if default == name else ""
    size = int(profile.get("llm_context_size", 0) or 0)
    capabilities = ", ".join(k for k, v in (profile.get("llm_capabilities") or {}).items() if v)
    return kit.detail_card(f"{name}{mark}", [
        ("Class", profile.get("llm_service_class", DEFAULT_BACKEND)),
        ("Context", "0 (reactive compaction)" if size == 0 else f"{size:,}"),
        ("Native attachments", capabilities or "none declared"),
    ])


def _label(name: str, default: str) -> str:
    """Menu label for a profile name."""
    if name == "add":
        return "Add profile"
    return f"{name} (default)" if default == name else name


def _value_prompt(field, backends: list[str]) -> str:
    """The prompt for the chosen edit field."""
    return {
        "llm_endpoint": ("Enter a provider base URL, or leave it blank for the "
                         "provider default."),
        "llm_model_name": "Enter the model name for this profile.",
        "llm_api_key": ("Enter the API key value or environment variable name. Leave "
                        "blank to let the backend read its own environment."),
        "llm_context_size": "Enter the context window size in tokens. Use 0 if unknown.",
        "llm_service_class": f"Enter one of: {', '.join(backends)}.",
        "llm_capability_image": "Can this model read images natively?",
        "llm_capability_audio": "Can this model read audio natively?",
        "llm_capability_video": "Can this model read video natively?",
    }.get(field, "Enter the new value.")

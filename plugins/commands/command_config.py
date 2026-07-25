"""Slash command plugin for `/config`."""

from plugins.BaseCommand import BaseCommand

ACTIONS = ["edit"]

# Browse gate: settings are shown one category at a time — there are too many to
# pick from a single flat list. Values are stable tokens (usable one-shot:
# `/config plugin`); labels are the button text. "all" is the explicit escape
# hatch that reproduces the flat everything-at-once view one tap deeper.
_REAL_CATEGORIES = ("kernel", "plugin", "user")
CATEGORIES = ["kernel", "plugin", "user", "all"]
_CATEGORY_LABELS = {
    "kernel": "Kernel Settings",
    "plugin": "Plugin Settings",
    "user": "User Settings",
    "all": "All Settings",
}
# Where each real category is stored — the section header on list views.
_CATEGORY_STORAGE = {
    "kernel": "config.json",
    "plugin": "plugin_config.json",
    "user": "per-user",
}


class ConfigCommand(BaseCommand):
    """Slash-command handler for `/config`.

    Two requests over two different kinds of knowledge, and keeping them apart is
    the whole design: the settings **catalog** (titles, types, owners, scope) is
    an ungated inventory read, because a declaration is as public as a plugin's
    name — while a setting's **value** goes through ``ReadConfig``, which is
    principal-graded, because a value may be an API key. Folding values into the
    catalog would route them around that gate.

    Values are read in one batch. Listing forty settings as forty round trips
    would be absurd, and it would put forty ledger rows behind one user action.
    """
    name = "config"
    description = "Select a config setting, then edit it"
    category = "Config & System"

    contract = "effects"
    declared_requests = ["read_context", "read_config", "write_config"]

    def form(self, params):
        """Walk category → (plugin) → setting → action → value."""
        catalog = yield from _catalog()
        category = params.get("category")
        steps = []

        if not params.get("setting_name"):
            # Required: the category gate is always the first thing browsed.
            # There is no one-shot `/config <setting>` fall-through — a setting is
            # always reached through its category or the explicit `all`. Required
            # also means the frontend never offers a redundant "skip", which would
            # just mean "all" and is already a button.
            steps.append({"name": "category", "required": True, "enum": CATEGORIES,
                          "enum_labels": [_CATEGORY_LABELS[c] for c in CATEGORIES],
                          "prompt": "Which settings do you want to browse?"})
            # Second drill-down, plugin settings only. Optional here is
            # meaningful rather than redundant: skipping shows every plugin
            # setting flat, which no single button offers.
            if category == "plugin":
                owners = sorted(_by_owner(catalog))
                steps.append({"name": "plugin_name", "required": False, "columns": 2,
                              "enum": owners, "enum_labels": owners,
                              "prompt_when_missing": True,
                              "prompt": "Which plugin's settings do you want to browse?"})

        visible = _filter(catalog, category, params.get("plugin_name"))
        steps.append({"name": "setting_name", "required": True, "columns": 2,
                      "enum": sorted(s["key"] for s in visible),
                      "prompt": "Select a setting to inspect or edit."})

        chosen = _find(catalog, params.get("setting_name"))
        if chosen:
            card = yield from _describe(chosen)
            steps.append({"name": "action", "required": True, "enum": ACTIONS,
                          "enum_labels": ["Edit setting"],
                          "prompt": f"What do you want to do with this setting?\n\n{card}"})
        if chosen and params.get("action") == "edit":
            steps.append(_value_step(chosen))
        return steps

    def run(self, params):
        """Execute `/config` for the active session."""
        from effects.vocabulary import Respond

        catalog = yield from _catalog()
        key = params.get("setting_name")
        if not key:
            listing = yield from _listing(catalog, params.get("category"),
                                          params.get("plugin_name"))
            return Respond(data=listing)

        setting = _find(catalog, key)
        if setting is None:
            return Respond(data=f"Unknown setting: {key}")
        if params.get("action") != "edit":
            return Respond(data=(yield from _describe(setting)))
        return (yield from apply_edit(setting, params.get("value")))


def apply_edit(setting: dict, raw_value):
    """Write one setting through the scope-aware path.

    Scope travels on the request: a user-scoped setting lands on the caller's
    config blob, a global one on the config file (and on plugin_config.json when
    a plugin declared it). The plugin no longer picks a writer.
    """
    import sandbox_kit as kit
    from effects.vocabulary import Respond, WriteConfig

    value = _coerce(setting, raw_value)
    result = yield WriteConfig(key=setting["key"], value=value, scope=setting["scope"])
    if not result.ok:
        return Respond(data=f"Could not set {setting['key']}: {result.error}")

    message = f"Set {setting['key']} = {kit.format_value(value)}"
    if (result.value or {}).get("restart_required"):
        message += ". Restart required."
    return Respond(data=message)


def _catalog():
    """Yield the settings catalog (declarations only, never values)."""
    from effects.vocabulary import ReadContext

    result = yield ReadContext(view="settings")
    return result.value or []


def _values(settings: list[dict]) -> dict:
    """Yield current values for *settings*, batched by scope.

    Two requests at most, not one per setting — user-scoped and global keys are
    stored in different places, so they cannot share a single read."""
    from effects.vocabulary import ReadConfig

    out = {}
    for scope in ("global", "user"):
        keys = [s["key"] for s in settings if s["scope"] == scope]
        if not keys:
            continue
        result = yield ReadConfig(keys=keys, scope=scope)
        out.update(result.value or {})
    return out


def _find(catalog, key):
    """One setting's declaration, or None."""
    return next((s for s in catalog if s["key"] == key), None) if key else None


def _by_owner(catalog) -> dict:
    """Plugin-category settings grouped by owning plugin.

    A setting declared by several plugins appears under each; ones with no known
    owner fall under "(unknown)"."""
    groups: dict = {}
    for setting in catalog:
        if setting["category"] != "plugin":
            continue
        for owner in setting["owners"] or ["(unknown)"]:
            groups.setdefault(owner, []).append(setting)
    return groups


def _filter(catalog, category=None, plugin_name=None) -> list[dict]:
    """The catalog narrowed to a browse category, and optionally one plugin."""
    if category == "plugin" and plugin_name:
        return _by_owner(catalog).get(plugin_name, [])
    if category not in _REAL_CATEGORIES:
        return list(catalog)
    return [s for s in catalog if s["category"] == category]


def _value_step(setting: dict) -> dict:
    """The value-entry step for one setting."""
    import sandbox_kit as kit

    return {"name": "value", "required": True,
            "type": kit.setting_type(setting),
            "prompt": kit.setting_prompt(setting)}


def _coerce(setting: dict, value):
    """Normalise a submitted value to the setting's declared type.

    Kept lenient on purpose: the value arrives as text from a form, and the
    kernel re-coerces through the form step anyway."""
    import json

    import sandbox_kit as kit

    kind = kit.setting_type(setting)
    if kind in ("array", "object") and isinstance(value, str):
        try:
            return json.loads(value or ("[]" if kind == "array" else "{}"))
        except (TypeError, ValueError):
            if kind == "array":
                return [line.strip() for line in value.splitlines() if line.strip()]
            return {}
    if kind == "boolean" and isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    if kind in ("integer", "number") and isinstance(value, str):
        try:
            return int(value) if kind == "integer" else float(value)
        except (TypeError, ValueError):
            return setting.get("default")
    return value


def _describe(setting: dict):
    """A describe card for one setting, including its current value."""
    import sandbox_kit as kit

    values = yield from _values([setting])
    tag = " (per-user)" if setting["scope"] == "user" else ""
    owners = setting["owners"] or []
    card = kit.detail_card(f"{setting['title']}{tag}", [
        (setting["key"], kit.format_value(values.get(setting["key"], setting.get("default")))),
        ("Used by", ", ".join(owners) if owners else "kernel"),
    ])
    description = (setting.get("description") or "").strip()
    out = card + (f"\n\n{kit.quote_block(description)}" if description else "")
    if len(owners) > 1:
        # Shared setting: one value, several plugins. An edit here is not local
        # to whichever plugin the user navigated in through.
        out += f"\n\n⚠ Shared setting — changing this also affects: {', '.join(owners)}."
    return out


def _listing(catalog, category=None, plugin_name=None):
    """The settings listing, grouped the way the browse gate implies."""
    if category == "plugin" and not plugin_name:
        groups = _by_owner(catalog)
        if not groups:
            return "No plugin settings found."
        values = yield from _values([s for group in groups.values() for s in group])
        return "\n\n".join(f"{owner}:\n\n" + _table(sorted(groups[owner], key=_key), values)
                           for owner in sorted(groups))

    if category == "plugin" and plugin_name:
        settings = _filter(catalog, "plugin", plugin_name)
        if not settings:
            return f"No settings for plugin: {plugin_name}"
        values = yield from _values(settings)
        return f"{plugin_name}:\n\n" + _table(sorted(settings, key=_key), values)

    wanted = [category] if category in _REAL_CATEGORIES else list(_REAL_CATEGORIES)
    shown = [s for s in catalog if s["category"] in wanted]
    values = yield from _values(shown)
    sections = []
    for name in wanted:
        settings = sorted((s for s in shown if s["category"] == name), key=_key)
        if not settings:
            continue
        header = f"{_CATEGORY_LABELS[name]} ({_CATEGORY_STORAGE[name]})"
        sections.append(f"{header}:\n\n" + _table(settings, values))
    return "\n\n".join(sections) or "No settings found."


def _table(settings: list[dict], values: dict) -> str:
    """A Setting/Value table."""
    import sandbox_kit as kit

    rows = [(s["key"], kit.format_value(values.get(s["key"], s.get("default"))))
            for s in settings]
    return kit.md_table(["Setting", "Value"], rows)


def _key(setting: dict) -> str:
    """Sort key."""
    return setting["key"]

"""Kernel inventory, as plain data.

The introspection commands — ``/commands``, ``/tools``, ``/tasks``,
``/services``, ``/frontends``, ``/debug`` — all answer "what exists right now?".
Today they answer it by holding live kernel objects: the command registry, the
orchestrator's task instances, ``session.cs``. That is exactly what a sandboxed
body cannot do, and it is why "it only reports, it does not mutate" turned out to
be the wrong test for whether a command could cross the boundary. Reading a live
object is as unsandboxable as mutating one.

So the kernel walks its own registries and hands back **names and static
metadata**. The plugin receives lists of dicts and does the formatting, which is
pure string work and the bulk of what these commands actually are.

Everything here is read-tier and non-secret by construction: it reports *what is
installed*, never configuration values or credentials. Where a plugin carries
settings, only the setting's declared metadata is exposed — never the current
value, which may hold an API key.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("Inventory")


def build_inventory(context):
    """Return ``(view) -> data`` over the live kernel, for ``ReadContext``.

    Closes over the context rather than taking one per call: the provider is
    built where the context is, and the plugin only ever names a view.
    """
    def inventory(view: str):
        """Resolve one inventory view to JSON-able data."""
        try:
            if view == "commands":
                return _commands(context)
            if view == "tools":
                return _tools(context)
            if view == "tasks":
                return _tasks(context)
            if view == "services":
                return _services(context)
            if view == "frontends":
                return _frontends(context)
            if view == "session_state":
                return _session_state(context)
            if view == "packages":
                return _packages(context)
            if view == "pipeline":
                return _pipeline(context)
            if view == "settings":
                return _settings_catalog()
            if view == "llm_backends":
                return _llm_backends()
            if view == "scheduled_jobs":
                return _scheduled_jobs()
        except Exception:  # noqa: BLE001 — introspection must not break a turn
            logger.exception("inventory view %r failed", view)
            return []
        raise ValueError(f"unknown inventory view {view!r}")

    return inventory


def _commands(context) -> list[dict]:
    """Registered slash commands, filtered by the session's frontend policy.

    The filter matters: a frontend profile can restrict which commands exist for
    a given frontend, and a listing that ignored that would advertise commands
    the caller cannot run."""
    registry = getattr(context, "command_registry", None)
    if registry is None:
        return []
    from plugins.frontends.helpers.command_registry import frontend_command_filter

    predicate = frontend_command_filter(getattr(context, "config", None), _frontend_of(context))
    return [{"name": c.name, "description": c.description,
             "category": c.category or "Other",
             "arg_hint": _arg_hint(c, context)}
            for c in registry.visible_commands(predicate)]


def _arg_hint(command, context) -> str:
    """The command's argument hint, derived from its form. Best-effort: a broken
    form must not remove the command from the listing."""
    try:
        from plugins.frontends.helpers.command_registry import _arg_hint_from_form
        return _arg_hint_from_form(command.form_steps({}, context)) or ""
    except Exception:  # noqa: BLE001
        return ""


def _tools(context) -> list[dict]:
    """Registered tools and their static metadata."""
    registry = getattr(context, "tool_registry", None)
    tools = (getattr(registry, "tools", {}) or {}) if registry else {}
    return [{"name": name,
             "description": _schema(tool).get("description", "")
                            or getattr(tool, "description", ""),
             # The JSON-schema parameter block, as data. /tools builds its
             # argument form from this rather than calling to_schema() on a live
             # object -- which is the whole point of the view.
             "parameters": _schema(tool).get("parameters") or {},
             "danger_tier": _safe(lambda: tool.danger_tier, ""),
             "contract": getattr(tool, "contract", "legacy"),
             "background_safe": bool(getattr(tool, "background_safe", True)),
             "declared_requests": list(getattr(tool, "declared_requests", []) or []),
             "settings": _settings(tool)}
            for name, tool in sorted(tools.items())]


def _schema(tool) -> dict:
    """A tool's OpenAI-style function schema, or an empty dict.

    Best-effort: one tool with a broken schema must not empty the catalog."""
    return _safe(lambda: tool.to_schema()["function"], {}) or {}


def _tasks(context) -> list[dict]:
    """Registered tasks, their trigger shape, and their run counts."""
    orch = getattr(context, "orchestrator", None)
    db = getattr(context, "db", None)
    tasks = (getattr(orch, "tasks", {}) or {}) if orch else {}
    counts = {}
    if db is not None:
        counts = (db.get_system_stats().get("tasks", {}) or {})
        if hasattr(db, "get_run_stats"):
            counts = counts | (db.get_run_stats() or {})
    paused = getattr(orch, "paused", set()) or set()
    jobs = _jobs_by_channel(context)
    return [{"name": name,
             "trigger": getattr(task, "trigger", "path"),
             "counts": counts.get(name, {}),
             "paused": name in paused,
             "requires_services": list(getattr(task, "requires_services", []) or []),
             "trigger_channels": list(getattr(task, "trigger_channels", []) or []),
             "event_payload_schema": getattr(task, "event_payload_schema", {}) or {},
             "scheduled_jobs": sum(
                 jobs.get(channel, 0)
                 for channel in (getattr(task, "trigger_channels", []) or [])),
             "settings": _settings(task)}
            for name, task in sorted(tasks.items())]


def _scheduled_jobs() -> list[dict]:
    """Every scheduled job, with its next fire time as an ISO string.

    Read-tier and ungated: a job definition is a channel name, a cron expression
    and a payload the caller supplied — the same class of fact as which tasks are
    registered. Changing one is ``ScheduleOp``; seeing them is this."""
    from runtime.scheduling import get_store

    return _safe(get_store().snapshot, []) or []


def _jobs_by_channel(context) -> dict:
    """How many scheduled jobs fire on each channel.

    Lets ``/tasks`` say "3 scheduled jobs". Reads the kernel's job store rather
    than the timekeeper service: the store is where the table lives now, and it
    is populated whether or not the service happens to be loaded."""
    counts: dict[str, int] = {}
    for job in _scheduled_jobs():
        channel = job.get("channel") or ""
        if channel:
            counts[channel] = counts.get(channel, 0) + 1
    return counts


def _pipeline(context) -> str:
    """The dependency-pipeline graph as pre-rendered text.

    The orchestrator already knows how to draw it and the drawing is not the
    plugin's business — so this crosses as a string rather than as a graph the
    command would have to lay out itself."""
    orch = getattr(context, "orchestrator", None)
    if orch is None or not hasattr(orch, "dependency_pipeline_graph"):
        return "Pipeline unavailable."
    return _safe(orch.dependency_pipeline_graph, "Pipeline unavailable.")


def _services(context) -> list[dict]:
    """Loaded and available services with their lifecycle and contract."""
    from plugins.BaseService import service_lifecycle

    services = getattr(context, "services", None) or {}
    autoload = set((getattr(context, "config", None) or {}).get("autoload_services") or [])
    from plugins.BaseService import is_extension_service, is_user_managed_service

    return [{"name": name,
             "model_name": getattr(svc, "model_name", name),
             "loaded": bool(getattr(svc, "loaded", False)),
             "lifecycle": service_lifecycle(svc),
             "contract": getattr(svc, "contract", "legacy"),
             "autoload": name in autoload,
             "shared": bool(getattr(svc, "shared", True)),
             "extension": is_extension_service(svc),
             "user_managed": is_user_managed_service(svc),
             "settings": _settings(svc)}
            for name, svc in sorted(services.items())]


def _settings(plugin) -> list[dict]:
    """A plugin's declared settings, as metadata only.

    Titles, keys, and type info — never current values. A setting's *value* may
    be an API key, so reading one is ``ReadConfig``, which is principal-graded.
    Its *declaration* is as public as the plugin's name."""
    out = []
    for entry in (getattr(plugin, "config_settings", None) or []):
        if not isinstance(entry, (list, tuple)) or len(entry) != 5:
            continue
        info = entry[4] if isinstance(entry[4], dict) else {}
        if info.get("hidden") is True:
            continue
        out.append({"title": entry[0], "key": entry[1], "prompt": entry[2],
                    "default": entry[3], "type_info": info})
    return out


def _frontends(context) -> list[dict]:
    """Configured frontends and whether each is currently enabled."""
    config = getattr(context, "config", None) or {}
    enabled = list(config.get("enabled_frontends") or [])
    profiles = config.get("frontend_profiles") or {}
    runtime = getattr(context, "runtime", None)
    manager = getattr(runtime, "frontend_manager", None)
    adapters = getattr(manager, "adapters", {}) or {}
    # Union of discovered, enabled, and profiled, so an entry stays editable
    # even after its plugin is removed.
    known = sorted(set(enabled) | set(adapters)
                   | set(getattr(manager, "available_frontends", ()) or ())
                   | set(profiles))
    return [{"name": name,
             "enabled": name in enabled,
             "running": name in adapters,
             "profile": profiles.get(name) or {},
             "settings": _settings(adapters.get(name))}
            for name in known]


def _session_state(context) -> dict:
    """A snapshot of the live state machine, as text blocks plus flags.

    ``/debug`` renders these; formatting stays plugin-side. The state machine
    object itself never leaves the kernel."""
    from state_machine.debug import format_recent_events, format_state

    runtime = getattr(context, "runtime", None)
    session_key = getattr(context, "session_key", None)
    session = ((getattr(runtime, "sessions", {}) or {}).get(session_key)
               if runtime and session_key else None)
    cs = getattr(session, "cs", None) if session else None
    if cs is None:
        return {"active": False}

    flags = [flag
             for svc in (getattr(context, "services", None) or {}).values()
             for flag in _safe(lambda: svc.debug_flags(session)
                               if callable(getattr(svc, "debug_flags", None)) else [], [])
             if flag]
    return {
        "active": True,
        "state": format_state(cs),
        "recent_events": format_recent_events(cs),
        "flags": flags,
        "busy": bool(getattr(session, "busy", False)),
    }


def _packages(context) -> dict:
    """What the store offers and what is installed, as three flat lists.

    Store lookups hit the network, so this is one round trip returning
    everything ``/packages`` needs rather than a request per view — the plugin
    filters by category itself, which is pure work."""
    from plugins.commands.helpers import package_manager

    root = getattr(context, "root_dir", None)
    installed = package_manager.installed_packages()
    installed_paths = {item["path"] for item in installed}
    available = [item for item in package_manager.search_packages(root)
                 if item["path"] not in installed_paths]
    bundles = package_manager.search_bundles(root)
    return {"installed": installed, "available": available,
            "removable": package_manager.removable_packages(),
            "bundles": bundles}


def _settings_catalog() -> list[dict]:
    """Every declared setting, as metadata — **never** current values.

    The split is the load-bearing part. A setting's *declaration* (its title,
    type, which plugins use it, whether it is user-scoped) is as public as a
    plugin's name and belongs on an ungated read. Its *value* may be an API key,
    so reading one is ``ReadConfig``, which is principal-graded. Putting values
    here would route them around that gate."""
    from config.config_data import SETTINGS_DATA
    from plugins.plugin_discovery import (
        get_plugin_setting_scope, get_plugin_settings, get_setting_plugin_names)

    plugin_entries = get_plugin_settings()
    plugin_keys = {entry[1] for entry in plugin_entries}

    out = []
    for title, key, description, default, info in [*SETTINGS_DATA, *plugin_entries]:
        info = info if isinstance(info, dict) else {}
        if info.get("hidden") is True:
            continue
        scope = ("user" if info.get("scope") == "user"
                 else (_safe(lambda k=key: get_plugin_setting_scope(k), "global")
                       if key in plugin_keys else "global"))
        owners = _safe(lambda k=key: get_setting_plugin_names(k), []) or []
        out.append({
            "key": key, "title": title, "description": description,
            "default": default, "type_info": info, "scope": scope,
            "owners": owners,
            "category": ("user" if scope == "user"
                         else "plugin" if key in plugin_keys else "kernel"),
        })
    return out


def _llm_backends() -> list[str]:
    """Which LLM backend classes are installed.

    A name list, not the classes: /llm offers these as an enum, and the plugin
    only ever needs to know what to call them."""
    from plugins.services.service_llm import llm_backend_names

    return _safe(llm_backend_names, []) or []


def _frontend_of(context):
    """Which frontend the calling session belongs to, if known."""
    runtime = getattr(context, "runtime", None)
    if not runtime:
        return None
    session = (getattr(runtime, "sessions", {}) or {}).get(getattr(context, "session_key", None))
    return getattr(session, "frontend_name", None)


def _safe(fn, default):
    """Call ``fn``, falling back to ``default``. One misbehaving plugin must not
    empty an entire inventory listing."""
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return default

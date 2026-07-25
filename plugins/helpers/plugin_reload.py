"""The kernel side of ``ReloadPlugin`` — registry mutation as a mediated verb.

``ReloadPlugin`` has existed in the vocabulary since the sandbox landed, with a
docstring explaining why loading a plugin is egress tier and a test proving the
interpreter routes it correctly. What it never had was a **provider**: no context
wired ``EffectContext.reload_plugin``, so nothing could actually issue one. Like
``ServiceTicker``, it was an exit built and never walked through — and for the
same reason, ``service_plugin_watcher`` kept citing capability #3 (mutates kernel
registries) long after the replacement for #3 was written.

This module is that provider. Everything the watcher used to do *around* the load
lives here now, because none of it is the watcher's business and all of it is
easy to forget:

- inferring which family a file belongs to, and refusing files that are not
  plugins at all,
- clearing the supervisor's strike count, so a fixed-and-resaved plugin gets a
  clean budget,
- rewiring peer services, refreshing the command specs and the LLM router,
  reconciling plugin config,
- announcing the result on the chat bus.

A plugin naming a path is the whole of its involvement. That is the difference
between a hot-reloader that *is* trusted and one that merely *runs* trusted.
"""

from __future__ import annotations

import logging
from pathlib import Path

from events.event_bus import bus
from events.event_channels import CHAT_MESSAGE_PUSHED

logger = logging.getLogger("PluginReload")


def _notify(message: str) -> None:
    """Announce a load/unload on the chat bus."""
    bus.emit(CHAT_MESSAGE_PUSHED,
             {"message": message, "kind": "plugin", "source": "plugin_watcher"})


def _registries(context) -> dict:
    """The live registries a load/unload needs, gathered from the context."""
    runtime = getattr(context, "runtime", None)
    return {
        "tool_registry": getattr(context, "tool_registry", None),
        "orchestrator": getattr(context, "orchestrator", None),
        "services": getattr(context, "services", None) or {},
        "command_registry": (getattr(context, "command_registry", None)
                             or getattr(runtime, "command_registry", None)),
        "frontend_manager": getattr(runtime, "frontend_manager", None),
        "runtime": runtime,
    }


def _names_registered_from(plugin_type: str, path: Path, reg: dict) -> list[str]:
    """Which registered names came from this file — for the deregistration notice."""
    source = str(path.resolve())
    if plugin_type == "tool":
        items = getattr(reg["tool_registry"], "tools", {}) or {}
    elif plugin_type == "task":
        items = getattr(reg["orchestrator"], "tasks", {}) or {}
    elif plugin_type == "command":
        items = getattr(reg["command_registry"], "_commands", {}) or {}
    elif plugin_type == "service":
        items = reg["services"]
    elif plugin_type == "frontend":
        items = {k: v.__class__
                 for k, v in (getattr(reg["frontend_manager"], "adapters", {}) or {}).items()}
    else:
        items = {}
    return [name for name, item in items.items()
            if getattr(item, "_source_path", "") == source]


def _refresh_commands(reg: dict) -> None:
    """Rebuild the runtime's command specs after a command file changed."""
    runtime, registry = reg["runtime"], reg["command_registry"]
    if runtime and registry and hasattr(registry, "to_callable_specs"):
        runtime.commands = registry.to_callable_specs()
    if runtime and hasattr(runtime, "refresh_session_specs"):
        runtime.refresh_session_specs()


def _refresh_llm_backends(reg: dict, config: dict) -> None:
    """Resync the LLM router after a service file changed. Best-effort."""
    try:
        from plugins.services.service_llm import refresh_llm_profile_services
    except Exception:  # noqa: BLE001 — the LLM service may not be installed
        return
    try:
        refresh_llm_profile_services(reg["services"], config)
    except Exception:  # noqa: BLE001 — a reload must not fail on resync
        logger.debug("llm router resync failed", exc_info=True)


def _reconcile_config(config: dict) -> None:
    """Re-apply plugin setting defaults after the plugin set changed."""
    try:
        import config.config_manager as cm

        from plugins.plugin_discovery import get_plugin_settings
        cm.reconcile_plugin_config(config, get_plugin_settings())
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Plugin config reconcile failed: {e}")


def _announce_quarantine(source_path: str, plugin_type: str, names: list[str]) -> bool:
    """If this path stands condemned, report the quarantine. Returns whether it did."""
    from events.event_channels import PLUGIN_QUARANTINED
    from runtime.supervisor import supervisor

    if not supervisor.health.is_quarantined(source_path):
        return False
    name = names[0] if names else source_path
    logger.error(f"Quarantined {plugin_type} '{name}' ({source_path})")
    _notify(f"Quarantined plugin: {name}")
    bus.emit(PLUGIN_QUARANTINED, {"plugin_type": plugin_type, "source_path": source_path,
                                  "name": name, "reason": ""})
    return True


def build_reload_plugin(context):
    """Return ``(path, action) -> summary dict`` for ``ReloadPlugin``.

    ``action`` is ``"reload"`` (load or re-load the file) or ``"unload"``
    (deregister it; the file itself is untouched). The return value is plain
    data — name, family, whether it worked — so a plugin can report the outcome
    without ever holding a registry.
    """
    from plugins.helpers.plugin_paths import plugin_info
    from plugins.plugin_discovery import load_single_plugin, unload_plugin, wire_peer_services

    config = getattr(context, "config", None) or {}

    def reload_plugin(raw_path: str, action: str = "reload") -> dict:
        """Load, reload, or unload one plugin file."""
        path = Path(raw_path).resolve()
        info, err = plugin_info(path)
        if err:
            if action == "reload":
                _notify(f"✕ Plugin registration failed: {path.name}\n{err}")
            return {"ok": False, "path": str(path), "error": err}

        reg = _registries(context)

        if action == "unload":
            if info.plugin_type == "frontend" and info.built_in:
                # git pull (e.g. /update) replaces files as delete+create; tearing
                # down a kernel frontend mid-churn kills the surface the user is
                # typing into. Built-in frontends only change on restart anyway.
                return {"ok": True, "path": str(path), "skipped": "built-in frontend"}
            names = _names_registered_from(info.plugin_type, path, reg)
            unload_plugin(info.plugin_type, "", source_path=str(path),
                          tool_registry=reg["tool_registry"], orchestrator=reg["orchestrator"],
                          services=reg["services"], command_registry=reg["command_registry"],
                          frontend_manager=reg["frontend_manager"])
            if info.plugin_type == "service":
                _refresh_llm_backends(reg, config)
            if info.plugin_type == "command":
                _refresh_commands(reg)
            _reconcile_config(config)
            if _announce_quarantine(str(path), info.plugin_type, names):
                # A condemned plugin's removal is reported as a quarantine, not
                # as an ordinary deregistration -- the user needs to know their
                # plugin was disabled *for misbehaving*, not merely that it went
                # away. The supervisor decides (policy); this is the mechanism
                # reporting that the decision took effect.
                return {"ok": True, "path": str(path), "type": info.plugin_type,
                        "names": names, "quarantined": True}
            for name in names:
                _notify(f"Deregistered plugin: {name}")
            logger.info(f"Unloaded {info.plugin_type}: {path.name}")
            return {"ok": True, "path": str(path), "type": info.plugin_type, "names": names}

        if action != "reload":
            return {"ok": False, "path": str(path), "error": f"unknown action {action!r}"}

        # A (re)load is a fresh start: forget any prior strikes/quarantine so a
        # fixed-and-resaved plugin gets a clean strike budget.
        try:
            from runtime.supervisor import supervisor
            supervisor.health.clear(str(path))
        except Exception:  # noqa: BLE001 — health tracking is advisory
            logger.debug("could not clear plugin health", exc_info=True)

        try:
            name, error = load_single_plugin(
                info.plugin_type, path, config=config,
                tool_registry=reg["tool_registry"], orchestrator=reg["orchestrator"],
                services=reg["services"], command_registry=reg["command_registry"],
                frontend_manager=reg["frontend_manager"], runtime=reg["runtime"])
        except Exception as e:  # noqa: BLE001 — a bad plugin is data, not a crash
            name, error = None, str(e)
        if error:
            logger.warning(f"Failed to load {path.name}: {error}")
            _notify(f"✕ Plugin registration failed: {name or path.name}\n{error}")
            return {"ok": False, "path": str(path), "type": info.plugin_type,
                    "name": name, "error": error}

        if info.plugin_type == "service":
            wire_peer_services(reg["services"])
        if info.plugin_type == "command":
            _refresh_commands(reg)
        _reconcile_config(config)
        _notify(f"✓ Registered plugin: {name}")
        logger.info(f"Loaded {info.plugin_type}: {name}")
        return {"ok": True, "path": str(path), "type": info.plugin_type, "name": name}

    return reload_plugin

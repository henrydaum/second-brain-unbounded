"""The kernel-side administration surface for the effects contract.

Kernel commands administer the system: ``/config`` saves settings, ``/services``
starts and stops, ``/packages`` installs, ``/conversations`` creates and deletes.
For those commands to run as pure generator bodies, administration has to be
reachable as a **request** rather than as a live import — which is what the four
administration verbs in ``effects/vocabulary.py`` provide, and what this module
serves.

It lives plugin-side rather than in ``runtime/`` for a reason the kernel-boundary
test enforces: it reaches ``package_manager``, a plugin implementation, and core
may not import those. Keeping it here also gives a second, structural line of
defense — only the command-registry context is wired with an administration
surface, so a tool has none to reach even before the principal check runs.

Authorization is **not** done here. By the time a request arrives the interpreter
has already applied the principal/provenance policy
(``effects/declarations.py``) and, where that said "ask", the approval surface.
This module is deliberately mechanical.
"""

from __future__ import annotations

from pipeline.database import DEFAULT_USER_ID


# Global settings the filesystem watcher reads. Changing any of these triggers a
# live rescan so syncing starts immediately rather than after a restart.
_WATCHER_KEYS = frozenset({
    "sync_directories", "ignored_extensions", "ignored_folders", "skip_hidden_folders",
})


def _is_plugin_setting(key: str) -> bool:
    """Whether *key* was declared by a plugin rather than by the kernel."""
    from plugins.plugin_discovery import get_plugin_settings

    return any(entry[1] == key for entry in get_plugin_settings())


def _needs_restart(key: str) -> bool:
    """Whether changing *key* only takes effect after a restart.

    Frontend settings are the case: a frontend's transport is started once at
    boot, so re-reading its config mid-run changes nothing."""
    from plugins.plugin_discovery import get_plugin_setting_type

    try:
        return get_plugin_setting_type(key) == "frontend"
    except Exception:  # noqa: BLE001 — an unknown key simply needs no restart
        return False


def _rescan_watcher(context) -> None:
    """Trigger a live watcher rescan, if the watcher is reachable."""
    watcher = getattr(getattr(context, "orchestrator", None), "watcher", None)
    if watcher is not None and hasattr(watcher, "rescan"):
        watcher.rescan()


def _progress_sink(runtime, session_key):
    """Where long-running administration reports its progress.

    Kernel-side on purpose. A pip install can run for minutes and the user needs
    to see movement, but handing the plugin a callback to report through is the
    "called back mid-operation" capability the boundary exists to avoid. The
    kernel already knows which session asked, so it pushes; the plugin stays a
    pure body that named an intent."""
    if runtime is not None and session_key and hasattr(runtime, "push_message"):
        return lambda message: runtime.push_message(session_key, message, source="packages")
    return lambda message: None


def build_administer(db, config: dict, services: dict, runtime, session_key: str | None,
                     context=None):
    """Return the callable that carries out administration requests.

    ``context`` is the live ``SecondBrainContext`` when one exists. It is passed
    through to machinery that already expects one (``package_manager`` records
    ledger rows from it) and is otherwise unused — the plugin never sees it.

    This is the kernel side of ``WriteConfig`` / ``ServiceControl`` /
    ``PackageOp`` / ``ConversationOp``. It exists so kernel commands can run on
    the effects contract: they administer the system, and administration has to
    be reachable as a *request* rather than as a live import if the command body
    is going to be a pure generator.

    Authorization already happened by the time this runs — the interpreter
    applied the principal/provenance policy and, where that said "ask", the
    approval surface. So this function is deliberately mechanical: it maps a
    request onto the machinery that already exists and does no policy of its own.
    Conversation ownership is the one exception, and only because the runtime
    enforces it internally on every by-id path.
    """
    def administer(request):
        """Carry out one administration request."""
        from config import config_manager

        rtype = request.type
        if rtype == "write_config":
            if request.scope == "user":
                if db is None or not runtime:
                    raise RuntimeError("user-scoped config needs a database and runtime")
                uid = runtime.session_user_id(session_key) if session_key else DEFAULT_USER_ID
                blob = db.get_user_config(uid)
                blob[request.key] = request.value
                db.set_user_config(uid, blob)
            else:
                saved = config_manager.load()
                saved[request.key] = request.value
                config_manager.save(saved)
                # Plugin-declared settings live in their own file as well, so a
                # plugin's setting survives independently of the kernel config.
                if _is_plugin_setting(request.key):
                    plugin_saved = config_manager.load_plugin_config()
                    plugin_saved[request.key] = request.value
                    config_manager.save_plugin_config(plugin_saved)
                # ``config`` here is the live kernel dict; write through so the
                # change takes effect without a restart, exactly as the imperative
                # commands did.
                if config is not None:
                    config[request.key] = request.value
                if runtime is not None and getattr(runtime, "config", None) is not None:
                    runtime.config[request.key] = request.value
            if runtime is not None and hasattr(runtime, "refresh_session_specs"):
                runtime.refresh_session_specs()
            # Watch-affecting keys take effect live: re-read directories and run
            # a fresh scan so syncing starts without a restart.
            if request.key in _WATCHER_KEYS:
                _rescan_watcher(context)
            return {"key": request.key, "scope": request.scope,
                    "restart_required": _needs_restart(request.key)}

        if rtype == "read_config":
            # No masking here on purpose. The protection is the principal
            # policy, not obfuscation: a human running /config to see their own
            # settings is not a threat to themselves, and that command has always
            # shown these values in plain text. The corner that matters --
            # untrusted code in an agent turn -- never reaches this function.
            if request.scope == "user":
                if db is None:
                    raise RuntimeError("user-scoped config needs a database")
                uid = runtime.session_user_id(session_key) if (runtime and session_key) else DEFAULT_USER_ID
                blob = db.get_user_config(uid)
                if request.keys is not None:
                    # Fall back to the effective config, which already merges the
                    # declared defaults -- otherwise a setting the user has never
                    # touched reads as None rather than as its default.
                    return {k: blob.get(k, (config or {}).get(k)) for k in request.keys}
                return blob.get(request.key, (config or {}).get(request.key))
            if request.keys is not None:
                return {k: (config or {}).get(k) for k in request.keys}
            return (config or {}).get(request.key)

        if rtype == "service_control":
            service = (services or {}).get(request.name)
            if service is None:
                raise RuntimeError(f"unknown service {request.name!r}")
            if request.action == "stop":
                service.unload()
            elif request.action in ("start", "reload"):
                if request.action == "reload":
                    service.unload()
                service.load()
            else:
                raise ValueError(f"unknown service action {request.action!r}")
            return {"name": request.name, "action": request.action,
                    "loaded": bool(getattr(service, "loaded", False))}

        if rtype == "package_op":
            from plugins.commands.helpers import package_manager

            root = getattr(context, "root_dir", None)
            progress = _progress_sink(runtime, session_key)
            action = request.action
            if action == "install":
                result = package_manager.install_package(
                    root, request.name, context, progress=progress)
            elif action == "uninstall":
                result = package_manager.uninstall_package(
                    request.name, context, progress=progress, root_dir=root)
            elif action == "update":
                result = package_manager.update_packages(root, context, progress=progress)
            else:
                raise ValueError(f"unknown package action {action!r}")
            return {"text": result.text(), "ok": bool(getattr(result, "ok", True))}

        if rtype == "task_control":
            import json
            from uuid import uuid4

            orch = getattr(context, "orchestrator", None)
            if orch is None:
                raise RuntimeError("no orchestrator available")
            task = (getattr(orch, "tasks", {}) or {}).get(request.name)
            if task is None:
                raise ValueError(f"unknown task {request.name!r}")
            event_driven = getattr(task, "trigger", "path") == "event"
            action = request.action

            if action in ("pause", "unpause"):
                orch.paused.add(request.name) if action == "pause" \
                    else orch.paused.discard(request.name)
                if action == "unpause":
                    orch.clear_skip_cache(request.name)
                return {"action": action, "name": request.name}

            if action in ("reset", "retry"):
                if event_driven:
                    raise ValueError(f"only path-driven tasks can be {action}")
                if db is None:
                    raise RuntimeError("no database available")
                (db.reset_task if action == "reset" else db.reset_failed_tasks)(request.name)
                orch.clear_skip_cache(request.name)
                return {"action": action, "name": request.name}

            if action == "trigger":
                if not event_driven:
                    raise ValueError("only event-driven tasks can be triggered manually")
                if db is None or not hasattr(db, "create_run"):
                    raise RuntimeError("no database is available for task runs")
                run_id = f"{request.name}:{uuid4().hex[:12]}"
                db.create_run(run_id, request.name, triggered_by="manual",
                              payload_json=json.dumps(request.payload or {}))
                if hasattr(orch, "on_run_enqueued"):
                    orch.on_run_enqueued(run_id, request.name)
                return {"action": action, "name": request.name, "run_id": run_id}

            raise ValueError(f"unknown task action {action!r}")

        if rtype == "conversation_op":
            if runtime is None:
                raise RuntimeError("no runtime available for conversation operations")
            fields = request.fields or {}
            action, cid = request.action, request.conversation_id
            if action == "create":
                return runtime.create_conversation(
                    fields.get("title") or "New conversation",
                    kind=fields.get("kind", "user"),
                    category=fields.get("category"),
                    user_id=runtime.session_user_id(session_key) if session_key else None)
            if action == "delete":
                return runtime.delete_conversation(session_key, cid)
            if action == "load":
                # load_history, not load_conversation: it reads the stored state
                # marker, so the agent profile follows the conversation. Returns
                # the runtime's own messages so the command can show them rather
                # than inventing its own wording.
                result = runtime.load_history(session_key, cid)
                if result is None:
                    return []
                return [m for m in (getattr(result, "messages", None) or []) if m] or True
            if action == "clear":
                # Kernel-side because it is four coupled steps that must not be
                # half-done: wipe messages, mark the title, then reload the
                # session *preserving its bound user* so the ownership guard
                # still sees the right identity on the way back in.
                if db is None:
                    raise RuntimeError("no database available to clear a conversation")
                if cid is None:
                    raise ValueError("clear needs a conversation_id")
                db.clear_conversation_messages(cid)
                conv = db.get_conversation(cid) or {}
                title = (conv.get("title") or "").strip()
                if title and not title.endswith(" (cleared)"):
                    db.update_conversation_title(cid, f"{title} (cleared)")
                uid = runtime.session_user_id(session_key)
                runtime.close_session(session_key)
                runtime.set_session_user(session_key, uid)
                runtime.load_conversation(session_key, cid)
                return True
            if action == "categorize":
                return runtime.set_conversation_category(session_key, cid, fields.get("category"))
            if action == "notification_mode":
                return runtime.set_conversation_notification_mode(session_key, cid, fields.get("mode"))
            raise ValueError(f"unknown conversation action {action!r}")

        raise ValueError(f"unhandled administration request {rtype!r}")

    return administer



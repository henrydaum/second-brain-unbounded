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


def build_administer(db, config: dict, services: dict, runtime, session_key: str | None):
    """Return the callable that carries out administration requests.

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
                # ``config`` here is the live kernel dict; write through so the
                # change takes effect without a restart, exactly as the imperative
                # commands did.
                if config is not None:
                    config[request.key] = request.value
                if runtime is not None and getattr(runtime, "config", None) is not None:
                    runtime.config[request.key] = request.value
                    if hasattr(runtime, "refresh_session_specs"):
                        runtime.refresh_session_specs()
            return {"key": request.key, "scope": request.scope}

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
            from plugins.helpers import package_manager
            if request.action == "install":
                return package_manager.install(request.name)
            if request.action == "uninstall":
                return package_manager.uninstall(request.name)
            raise ValueError(f"unknown package action {request.action!r}")

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
                return runtime.load_conversation(session_key, cid) is not None
            if action == "categorize":
                return runtime.set_conversation_category(session_key, cid, fields.get("category"))
            if action == "notification_mode":
                return runtime.set_conversation_notification_mode(session_key, cid, fields.get("mode"))
            raise ValueError(f"unknown conversation action {action!r}")

        raise ValueError(f"unhandled administration request {rtype!r}")

    return administer



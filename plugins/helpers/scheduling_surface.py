"""The kernel side of ``ScheduleOp`` — mechanical, like ``administration``.

Maps one scheduling request onto :mod:`runtime.scheduling`'s job store and hands
back ``(value, undo)``. The undo half is the whole reason this is a separate
function rather than three lines in the interpreter: ``ScheduleOp`` is graded
*write*, and a write tier is a promise the turn can be rolled back. So every
mutation captures the rows it is about to touch and closes over them.

Unlike ``build_administer`` this is wired for **every** family, because
scheduling is not administration. A job is a promise to emit on a channel, and
what that costs is decided at the emit by ``channel_danger_tier`` — the same
place, and the same reasoning, as any other bus event.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("Scheduling")


def build_schedule(config: dict | None = None):
    """Return ``(request) -> (value, undo)`` over the process-wide job store."""
    from runtime.scheduling import get_store

    def schedule(request):
        """Carry out one scheduling request, returning its value and its undo."""
        store = get_store(config)
        action = request.action

        if action == "create":
            state = store.capture([request.name])
            value = store.create_job(request.name, request.job or {})
            return value, lambda: store.restore(state)

        if action == "update":
            state = store.capture([request.name])
            value = store.update_job(request.name, request.job or {})
            return value, lambda: store.restore(state)

        if action == "enable":
            state = store.capture([request.name])
            value = store.enable_job(request.name, request.enabled)
            return value, lambda: store.restore(state)

        if action == "remove":
            state = store.capture([request.name])
            value = store.remove_job(request.name)
            return value, lambda: store.restore(state)

        if action == "advance":
            names = list(request.names or ([request.name] if request.name else []))
            state = store.capture(names)
            removed = store.advance(names, request.fired_at or {})
            return {"advanced": names, "removed": removed}, lambda: store.restore(state)

        raise ValueError(f"unknown schedule action {action!r}")

    return schedule

"""Kernel-side reads over the caller's own conversations.

Serves ``ReadConversations``. The whole reason that verb can be read-tier lives
here: **every query is scoped to the caller's ``user_id``**. A plugin names a
shape — a list, the categories, one preview — and never a user, so there is no
argument it can vary to reach someone else's history. That is the same
argument-level authorization ``read_roots`` provides for files.

Marker parsing (which agent profile, which notification mode) happens here too,
because it means decoding the state marker the runtime writes into the message
stream — kernel format, not plugin business.
"""

from __future__ import annotations

import logging
import time

logger = logging.getLogger("Conversations")

MAIN = "Main"
_PREVIEW_TURNS = 2
_SNIPPET_CHARS = 120


def build_reader(context):
    """Return ``(request) -> data`` over the caller's conversations."""
    def read(request):
        """Resolve one ReadConversations request."""
        db = getattr(context, "db", None)
        if db is None:
            raise RuntimeError("no database available")
        user_id = getattr(context, "user_id", None)

        if request.mode == "categories":
            return _categories(db, user_id)
        if request.mode == "list":
            return _list(db, user_id, request.category, request.limit)
        if request.mode == "preview":
            return _preview(db, user_id, request.conversation_id)
        raise ValueError(f"unknown conversation read mode {request.mode!r}")

    return read


def _categories(db, user_id) -> list[str]:
    """Distinct category labels for this user, blanks surfaced as ``Main``."""
    out: list[str] = []
    for value in db.list_conversation_categories(user_id=user_id):
        label = MAIN if value in (None, "") else value
        if label not in out:
            out.append(label)
    return out


def _list(db, user_id, category, limit) -> list[dict]:
    """Recent conversations for this user, newest first."""
    stored = "" if category in (MAIN, None) else category
    rows, _ = db.list_conversations_page(
        offset=0, limit=max(1, int(limit or 15)),
        category=stored, user_id=user_id)
    return [{"id": row.get("id"),
             "title": (row.get("title") or "").strip() or "(untitled)",
             "category": row.get("category") or MAIN,
             "updated_at": row.get("updated_at"),
             "relative_time": _relative_time(row.get("updated_at"))}
            for row in rows]


def _preview(db, user_id, conversation_id) -> dict:
    """One conversation's header facts and last couple of turns.

    Returns ``{}`` when the conversation does not belong to this user. The check
    is what lets a *read* of an arbitrary id be safe: the plugin supplies the id,
    the kernel decides whether that id is the caller's to see."""
    if conversation_id is None:
        return {}
    row = db.get_conversation(conversation_id) if hasattr(db, "get_conversation") else None
    if not row:
        return {}
    owner = row.get("user_id")
    if user_id is not None and owner is not None and owner != user_id:
        logger.warning("refused cross-user conversation preview for #%s", conversation_id)
        return {}

    messages = db.get_conversation_messages(conversation_id) or []
    marker = _marker(messages)
    snippets = []
    for message in reversed(messages):
        if message.get("role") not in ("user", "assistant"):
            continue
        content = (message.get("content") or "").strip()
        if not content:
            continue
        snippets.append(f"{message['role']}: {_truncate(content, _SNIPPET_CHARS)}")
        if len(snippets) >= _PREVIEW_TURNS:
            break
    snippets.reverse()

    return {"id": conversation_id,
            "title": (row.get("title") or "").strip() or "(untitled)",
            "agent": _agent(marker) or "(unknown)",
            "notification_mode": _notification_mode(marker),
            "snippets": snippets}


def _marker(messages) -> dict:
    """The latest state marker in a message stream, or an empty dict."""
    from state_machine.serialization import latest_state

    try:
        return latest_state(messages) or {}
    except Exception:  # noqa: BLE001 — a malformed marker must not break a preview
        logger.debug("could not parse state marker", exc_info=True)
        return {}


def _agent(marker: dict) -> str:
    """Which agent profile this conversation was last using."""
    return (marker.get("profile_override") or marker.get("active_agent_profile") or "").strip()


def _notification_mode(marker: dict) -> str:
    """This conversation's notification mode, normalised."""
    from runtime.notifications import notification_mode

    return notification_mode(marker.get("notification_mode"))


def _truncate(text: str, limit: int) -> str:
    """One-line, length-capped preview of a message body."""
    text = text.replace("\n", " ").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _relative_time(timestamp) -> str:
    """Format a timestamp as a coarse "N units ago" string."""
    try:
        seconds = max(0.0, time.time() - float(timestamp))
    except (TypeError, ValueError):
        return ""
    units = ((60, "second", "seconds"), (60, "minute", "minutes"),
             (24, "hour", "hours"), (7, "day", "days"),
             (4, "week", "weeks"), (12, "month", "months"),
             (None, "year", "years"))
    value = seconds
    for step, singular, plural in units:
        if step is None or value < step:
            count = int(value) if value >= 1 else 1
            if singular == "second" and count < 5:
                return "just now"
            return f"{count} {singular if count == 1 else plural} ago"
        value /= step
    return ""

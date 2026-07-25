"""Slash command plugin for `/debug`."""

from plugins.BaseCommand import BaseCommand


class DebugCommand(BaseCommand):
    """Slash-command handler for `/debug`.

    Read-only introspection of the active conversation: what the state machine
    currently thinks is happening, plus the tail of recent log warnings/errors.
    Useful when a form, approval, or phase flow gets stuck.

    Note this command is the clearest case that "read-only" is *not* the same as
    "sandboxable". It mutates nothing, but it used to hold ``session.cs`` and
    call ``svc.debug_flags(session)`` on live service objects — live handles,
    which no sandboxed body can have. The kernel now renders the snapshot to text
    and this body only assembles it.
    """
    name = "debug"
    description = "Inspect the live conversation state machine and recent log errors"
    category = "System"

    contract = "effects"
    declared_requests = ["read_context", "read_file"]

    def run(self, _params):
        """Execute `/debug` for the active session."""
        from effects.vocabulary import ReadContext, ReadFile, Respond

        state = yield ReadContext(view="session_state")
        paths = yield ReadContext(view="paths")

        log_path = f"{(paths.value or {}).get('data', '')}/app.log"
        log = yield ReadFile(path=log_path)

        # Fenced blocks: rich renderers collapse single newlines in prose, so the
        # multi-line dumps must travel as code to stay readable.
        return Respond(data=(
            "**Conversation state**\n```\n" + _state_section(state) + "\n```\n\n"
            "**Recent log warnings/errors**\n```\n"
            + "\n".join(_log_lines(log, log_path)) + "\n```"
        ))


def _state_section(result) -> str:
    """Assemble the state-machine snapshot from the kernel's inventory view."""
    snapshot = result.value if result.ok else None
    if not snapshot or not snapshot.get("active"):
        return "(no active session)"

    parts = [snapshot.get("state") or ""]
    flags = [f for f in (snapshot.get("flags") or []) if f]
    if flags:
        parts.append("Session: " + ", ".join(flags))
    if snapshot.get("busy"):
        parts.append("Session: agent turn in progress")
    parts.append(snapshot.get("recent_events") or "")

    return "\n".join(line for block in parts for line in block.splitlines())


def _log_lines(result, path: str, limit: int = 10) -> list[str]:
    """Return recent warning/error/critical log lines."""
    if not result.ok:
        return [f"No log file found at {path}."]
    hits = [
        line.strip()
        for line in (result.value or "").splitlines()
        if " | WARNING | " in line or " | ERROR | " in line or " | CRITICAL | " in line
    ]
    return hits[-limit:] or ["No warnings or errors in this run."]

"""Slash command plugin for `/cancel`."""

from plugins.BaseCommand import BaseCommand


class CancelCommand(BaseCommand):
    """Slash-command handler for `/cancel`.

    Uses ``SessionAction`` rather than ``ConversationOp``: a session is the
    ephemeral in-flight interaction, a conversation is durable owned state.
    Cancelling a form stores nothing and destroys nothing, so folding the two
    together would put it behind the same gate as deleting history.
    """
    name = "cancel"
    description = "Cancel the current interaction"
    category = "Conversation"

    contract = "effects"
    declared_requests = ["session_action"]

    def run(self, _params):
        """Execute `/cancel` for the active session."""
        from effects.vocabulary import Respond, SessionAction

        result = yield SessionAction(action="cancel")
        if not result.ok:
            return Respond(data="No active session to cancel.")

        outcome = result.value or {}
        if outcome.get("messages"):
            return Respond(data="\n".join(outcome["messages"]))
        if outcome.get("error"):
            return Respond(data=outcome["error"])
        if not outcome.get("ok", True):
            return Respond(data="Nothing to cancel.")
        return Respond(data="Cancelled.")

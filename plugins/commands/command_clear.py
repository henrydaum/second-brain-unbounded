"""Slash command plugin for `/clear`."""

from plugins.BaseCommand import BaseCommand


class ClearCommand(BaseCommand):
    """Slash-command handler for `/clear`.

    Clearing is four coupled steps — wipe messages, mark the title, close the
    session, reload it preserving the bound user — that must not be half-done.
    So the body names the *intent* and the kernel carries out the sequence,
    rather than the plugin driving four mutations and owning the ordering.
    """
    name = "clear"
    description = "Clear all messages in the current conversation"
    category = "Conversation"

    contract = "effects"
    declared_requests = ["conversation_op", "read_context"]

    def run(self, _params):
        """Execute `/clear` for the active session."""
        from effects.vocabulary import ConversationOp, ReadContext, Respond

        current = yield ReadContext(view="conversation_id")
        conversation_id = current.value
        if conversation_id is None:
            return Respond(data="No conversation loaded.")

        done = yield ConversationOp(action="clear", conversation_id=conversation_id)
        if not done.ok:
            return Respond(data=f"Could not clear the conversation: {done.error}")
        return Respond(data="Conversation cleared.")

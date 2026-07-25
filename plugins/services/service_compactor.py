"""Conversation compaction service."""

from plugins.BaseService import BaseService, EXTENSION


class CompactorService(BaseService):
    """Summarize conversation history when the active LLM context is tight."""

    model_name = "Conversation Compactor"
    lifecycle = EXTENSION

    SYSTEM_PROMPT = (
        "Produce a continuation summary of this Second Brain conversation that a "
        "fresh assistant instance can resume from without re-reading the transcript. "
        "Cover, in order: the user's goal and their current request; decisions made "
        "and why; files, tables, config keys, and conversation/task IDs touched "
        "(exact paths and identifiers, never paraphrases); tool results that are "
        "still relevant; anything promised or in progress; and the concrete next "
        "step. Prefer exact identifiers over description — a wrong or vague path "
        "is worse than a long one. Omit pleasantries and abandoned approaches, "
        "unless knowing an approach failed prevents repeating the mistake."
    )

    # Compaction is pure text work over one model call, so it needs none of the
    # five capabilities that force the always-trusted exception (see
    # effects/PRIMITIVES.md): no live handle, no thread, no registry mutation,
    # no mid-operation callback, no callable handed to the kernel. It is
    # therefore an ordinary sandboxable service — and the first one to prove a
    # service can cross the boundary at all.
    contract = "effects"
    declared_requests = ["complete"]

    def compact(self, params):
        """Return a continuation summary for a rendered transcript.

        The LLM is reached as a ``Complete`` request rather than as an object, so
        keys and sockets stay kernel-side. The kernel resolves *which* model —
        the session's profile-selected brain, matching the conversation being
        compacted — before the request is served."""
        from effects.vocabulary import Complete, Respond

        transcript = (params or {}).get("transcript") or ""
        if not transcript:
            return Respond(data="")
        answer = yield Complete(prompt=transcript, system=self.SYSTEM_PROMPT)
        if not answer.ok:
            # Compaction failing is not fatal: the loop keeps the history it has
            # and warns. Returning None keeps that contract.
            return Respond(success=False, error=answer.error, data=None)
        return Respond(data=(str(answer.value or "")).strip())


def build_services(config: dict) -> dict:
    return {"compactor": CompactorService()}

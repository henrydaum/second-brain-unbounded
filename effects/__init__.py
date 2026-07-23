"""The effect system — the trusted boundary between pure tools and the world.

A tool's only wire to the world is yielding **typed requests** from this closed
vocabulary to a kernel-side interpreter (``effects.interpreter``). The
interpreter fulfils each request and hands the result back, so the tool code
itself never holds a db handle, a socket, or a filesystem cursor.

Three tiers grade every request (``effects.vocabulary``):

- ``read``   — local reads, always safe.
- ``write``  — reversible writes; journalled so a turn can be rolled back.
- ``egress`` — boundary-crossing transmission (HTTP, LLM completion); gated,
  because any transmission is exfiltration-capable regardless of verb.

A tool *declares* the request types it may issue (``effects.declarations``); its
danger tier is **derived** from those declarations, never author-asserted, and
an undeclared request at runtime is a hard reject. The request stream is the
action ledger.
"""

from effects.vocabulary import (
    TIER_READ,
    TIER_WRITE,
    TIER_EGRESS,
    TIER_ORDER,
    Request,
    ReadFile,
    QueryDb,
    ReadContext,
    WriteFile,
    WriteDb,
    Respond,
    HttpRequest,
    Complete,
    REQUEST_TYPES,
    from_wire,
    request_class,
)
from effects.declarations import (
    derive_tier,
    validate_declared,
    UndeclaredRequestError,
)
from effects.interpreter import (
    EffectContext,
    EffectResult,
    Interpreter,
    TurnJournal,
    EgressDenied,
)

__all__ = [
    "TIER_READ",
    "TIER_WRITE",
    "TIER_EGRESS",
    "TIER_ORDER",
    "Request",
    "ReadFile",
    "QueryDb",
    "ReadContext",
    "WriteFile",
    "WriteDb",
    "Respond",
    "HttpRequest",
    "Complete",
    "REQUEST_TYPES",
    "from_wire",
    "request_class",
    "derive_tier",
    "validate_declared",
    "UndeclaredRequestError",
    "EffectContext",
    "EffectResult",
    "Interpreter",
    "TurnJournal",
    "EgressDenied",
]

"""Deriving a tool's danger tier from what it *declares*, not what it asserts.

A tool ships a ``declared_requests`` list of wire tags (e.g.
``["read_file", "complete"]``). Two things fall out of it:

- ``derive_tier(...)`` — the tool's danger tier is the maximum tier across its
  declared request types. Author-asserted danger is never trusted; the tier is
  computed from the closed vocabulary.
- ``validate_declared(...)`` — at fulfilment time a request whose type is not in
  the tool's declaration is a hard reject (``UndeclaredRequestError``). This is
  the executable half of "tools declare their request types; an undeclared
  attempt is a hard reject."

The tags themselves are validated against ``REQUEST_TYPES`` so a typo in a
declaration surfaces at load time, not as a silent capability gap.
"""

from __future__ import annotations

from collections.abc import Iterable

from effects.vocabulary import TIER_ORDER, TIER_READ, REQUEST_TYPES, Request


class UndeclaredRequestError(RuntimeError):
    """A tool issued a request type it did not declare."""

    def __init__(self, tool_name: str, request_type: str, declared: Iterable[str]):
        """Initialize the undeclared-request error."""
        self.tool_name = tool_name
        self.request_type = request_type
        self.declared = sorted(declared)
        super().__init__(
            f"tool {tool_name!r} issued undeclared request {request_type!r}; "
            f"declared: {self.declared}"
        )


def _validate_tags(declared: Iterable[str]) -> list[str]:
    """Return the declared tags, raising on any not in the vocabulary."""
    tags = list(declared or [])
    unknown = [t for t in tags if t not in REQUEST_TYPES]
    if unknown:
        raise ValueError(
            f"unknown declared request type(s): {unknown}; "
            f"valid types are {sorted(REQUEST_TYPES)}"
        )
    return tags


def derive_tier(declared: Iterable[str]) -> str:
    """Return the max tier across declared request tags.

    A tool declaring nothing is tier ``read`` (it can still ``Respond`` and
    ``ReadContext`` — those are implicitly available and read-tier).
    """
    tags = _validate_tags(declared)
    tier = TIER_READ
    for tag in tags:
        cls = REQUEST_TYPES[tag]
        if TIER_ORDER[cls.tier] > TIER_ORDER[tier]:
            tier = cls.tier
    return tier


# ``Respond`` and ``ReadContext`` are always available: every tool must be able
# to return a value and to see the slice of context its declared view grants.
# They never need to be declared and never count toward danger tier.
IMPLICIT_REQUESTS: frozenset[str] = frozenset({"respond", "read_context"})


def validate_declared(tool_name: str, request: Request, declared: Iterable[str]) -> None:
    """Raise ``UndeclaredRequestError`` if ``request`` is not permitted.

    A request is permitted when its type is implicitly available or appears in
    the tool's declarations.
    """
    rtype = request.type
    if rtype in IMPLICIT_REQUESTS:
        return
    if rtype not in set(declared or ()):
        raise UndeclaredRequestError(tool_name, rtype, declared or ())


# ── who is asking ────────────────────────────────────────────────────────
#
# Tier answers "how dangerous is this operation?" and is a property of the
# operation alone. It is not the whole question for the administration verbs:
# `/config` saving a setting is the *user* acting on their own system, while an
# agent-authored tool saving the same setting is something else entirely. Same
# verb, same tier, different principal.
#
# This generalises the rule already in PRIMITIVES.md — "the security level of a
# request is based on what it triggers, which can depend" — from *what* to
# *who*, and it is the only place that generalisation is encoded.

PRINCIPAL_USER = "user"
PRINCIPAL_AGENT = "agent"

# The requests this policy governs. Everything else is decided by tier alone;
# keeping the set explicit means adding a verb does not silently opt it in.
ADMIN_REQUESTS: frozenset[str] = frozenset({
    "write_config", "service_control", "package_op", "conversation_op",
})

ALLOW, APPROVE, REFUSE = "allow", "approve", "refuse"


def admin_disposition(principal: str, plugin_trusted: bool) -> str:
    """How an administration request should be treated, given both ceilings.

    **Principal is derived from the dispatch path, never from the plugin's
    family.** A slash command is the user acting; a tool call inside an agent
    turn is the agent acting. Deriving it from the family would make a
    command/tool bridge into a privilege escalation — the agent calls a tool
    that calls a command that saves config — so the principal travels on the
    context and a caller propagates it rather than minting a fresh one.

    **Provenance is the second ceiling**, and it is why one axis is not enough.
    The agent can write a command into ``sandbox_plugins/`` and wait for the user
    to run it, laundering agent authority into user authority. Requiring both
    axes closes that: an untrusted body never gets a silent administration pass,
    whoever happens to be invoking it.

    ============  ==================  ====================
    principal     trusted plugin      untrusted plugin
    ============  ==================  ====================
    user          allow               approve
    agent         approve             refuse
    ============  ==================  ====================
    """
    if principal == PRINCIPAL_USER:
        return ALLOW if plugin_trusted else APPROVE
    return APPROVE if plugin_trusted else REFUSE

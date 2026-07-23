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

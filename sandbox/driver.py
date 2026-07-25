"""The transport-agnostic generator driver — shared by both execution modes.

A plugin body is a generator: it yields typed requests and receives their
fulfilments, ending by returning (or yielding) a ``Respond``. *Driving* that
generator is identical no matter where the body runs; the only thing that
differs is how a yielded request gets fulfilled:

- **untrusted** (``sandbox/entry.py``) — write the request down a pipe and block
  for the parent's reply.
- **trusted** (``sandbox/local.py``) — call the ``Interpreter`` directly.

Both pass a ``fulfil(request_wire) -> result_wire`` callable to :func:`drive`.
Sharing this loop is what makes "trusted mode is not a bypass" structural rather
than aspirational: there is one implementation of the tool→kernel conversation,
so the two modes cannot silently diverge in ordering, in how a ``Respond`` is
recognised, or in what a non-generator body means.

This module has **no kernel imports** on purpose — the restricted child imports
it too, and importing it must not widen the child's surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


class Result:
    """What a plugin sees back from ``yield <request>`` — one effect result."""

    __slots__ = ("ok", "value", "error", "denied")

    def __init__(self, wire: dict):
        """Build from an effect-result wire dict."""
        self.ok = bool(wire.get("ok", True))
        self.value = wire.get("value")
        self.error = wire.get("error", "")
        self.denied = bool(wire.get("denied", False))


@dataclass
class SandboxOutcome:
    """Neutral result of a plugin run, in either mode.

    Deliberately not a ``ToolResult``: the executors know nothing about plugin
    families. The family adapter maps this onto whatever its registry expects.
    """

    success: bool = True
    summary: str = ""
    data: Any = None
    error: str = ""
    error_type: str = ""
    attachment_paths: list[str] = field(default_factory=list)

    @classmethod
    def failed(cls, error: str, error_type: str = "SandboxError") -> "SandboxOutcome":
        """Build a failed outcome."""
        return cls(success=False, error=error, error_type=error_type)


def as_final(value) -> dict:
    """Coerce a body's return value into a ``Respond`` wire dict."""
    if value is None:
        raise RuntimeError("tool finished without a Respond")
    if hasattr(value, "to_wire"):
        return value.to_wire()
    if isinstance(value, dict) and value.get("type") == "respond":
        return value
    # A bare value: wrap it as a successful Respond payload.
    return {"type": "respond", "summary": str(value), "data": value, "success": True, "error": ""}


def drive(instance, params: dict, fulfil: Callable[[dict], dict], method: str = "run") -> dict:
    """Drive one plugin body to completion. Returns the final ``Respond`` wire.

    ``fulfil`` receives a request wire dict and returns an effect-result wire
    dict. A body that is not a generator (it returned a ``Respond`` outright) is
    supported and never calls ``fulfil`` — that is a legitimate pure plugin, not
    an error.

    ``method`` names the body to drive. It is almost always ``run``, but some
    families have a second entry point that also needs effects — a command's
    ``form`` must be able to read the world to build its choices — and those
    travel the same path rather than getting a privileged side channel.

    A ``respond`` yielded mid-stream ends the run without being fulfilled: it is
    the terminal request, not an effect.
    """
    body = getattr(instance, method, None)
    if body is None:
        raise RuntimeError(f"plugin has no {method!r} method")
    result = body(params)
    if not hasattr(result, "send"):
        return as_final(result)

    to_send = None
    while True:
        try:
            request = result.send(to_send)
        except StopIteration as stop:
            return as_final(stop.value)
        wire = request.to_wire() if hasattr(request, "to_wire") else dict(request)
        if wire.get("type") == "respond":
            return wire
        to_send = Result(fulfil(wire) or {})


def outcome_from_respond(wire: dict) -> SandboxOutcome:
    """Map a ``Respond`` wire dict onto a :class:`SandboxOutcome`."""
    wire = wire or {}
    return SandboxOutcome(
        success=bool(wire.get("success", True)),
        summary=wire.get("summary") or "",
        data=wire.get("data"),
        error=wire.get("error") or "",
        attachment_paths=list(wire.get("attachment_paths") or []),
    )

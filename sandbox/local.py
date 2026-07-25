"""The trusted execution mode: run a plugin body in-process.

The counterpart to ``sandbox/runner.py``. Same contract, same generator loop
(``sandbox.driver.drive``), same ``Interpreter`` — the only difference is that
no subprocess exists, so there is no spawn cost, no import gate, and a traceback
points at the real source line.

**This is not a bypass.** Every request still travels through the interpreter, so
declarations, tiers, argument-level checks, journalling, the egress gate, and
ledger rows are identical to the untrusted path. What trusted mode buys is
speed (~33 ms of spawn) and debuggability, not authority. A trusted plugin still
yields ``QueryDb``; it never receives a live ``db``.

The mode is chosen by *provenance* — see ``plugins.helpers.plugin_paths.is_trusted``
— never by anything the plugin asserts about itself.

Deliberately absent, because the code is trusted: the AST import gate
(``validate.py``), the restricted-builtins ``exec``, the memory watchdog, and the
wall-clock kill. A trusted plugin that hangs hangs the caller, exactly as any
in-process kernel code would; that is the cost of trusting it.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from effects.declarations import UndeclaredRequestError
from effects.interpreter import EffectContext, Interpreter, TurnJournal
from effects.vocabulary import from_wire
from sandbox.driver import SandboxOutcome, drive, outcome_from_respond

logger = logging.getLogger("Sandbox.local")


def _interpreter_fulfil(interp: Interpreter):
    """The trusted mode's fulfilment: call the interpreter directly.

    Mirrors ``sandbox.entry._pipe_fulfil`` exactly, minus the pipe. The request
    is still rebuilt through ``from_wire`` rather than passed as a live object,
    so a malformed request fails the same way in both modes and the wire format
    stays the single description of what a request *is*.
    """
    def fulfil(wire: dict) -> dict:
        request = from_wire(wire)
        return interp.fulfill(request).to_wire()

    return fulfil


def run_local_tool(
    *,
    instance: Any,
    params: dict,
    declared: list[str],
    effect_ctx: EffectContext,
    journal: TurnJournal | None = None,
) -> SandboxOutcome:
    """Run one trusted plugin body in-process. Returns a :class:`SandboxOutcome`.

    ``instance`` is an already-constructed plugin object (discovery imported and
    instantiated it normally). ``declared`` is its declared request tags; the
    interpreter hard-rejects anything undeclared, exactly as in the subprocess.
    """
    interp = Interpreter(effect_ctx, declared, journal=journal)
    started = time.perf_counter()
    try:
        final = drive(instance, dict(params or {}), _interpreter_fulfil(interp))
    except UndeclaredRequestError as e:
        # A contract violation, not a failed run — same classification the
        # subprocess runner gives it.
        return SandboxOutcome.failed(str(e), "UndeclaredRequest")
    except Exception as e:  # noqa: BLE001 — a raising body is a failed run, not a crash
        logger.debug("trusted plugin %r raised: %s",
                     getattr(instance, "name", "?"), e, exc_info=True)
        return SandboxOutcome.failed(str(e), type(e).__name__)
    logger.debug("trusted run of %r finished in %.1f ms",
                 getattr(instance, "name", "?"), (time.perf_counter() - started) * 1000)
    return outcome_from_respond(final)

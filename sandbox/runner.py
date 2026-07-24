"""The parent-side sandbox boss: spawn the child, fulfil its requests, return.

``run_sandbox_tool`` drives one tool run end to end: validate the source, spawn
the child (``python -I``), and pump the JSON-lines protocol — each yielded
request is fulfilled through an :class:`~effects.interpreter.Interpreter` (which
enforces declarations, tiers, journalling, and the egress gate) and the result
is fed back to the child. A wall-clock deadline and a reader thread keep the pump
responsive and cross-platform (Windows pipes have no ``select``); overrunning the
deadline kills the child.

This module imports only stdlib + ``effects`` + ``sandbox``: no ``plugins.*``
edge, so ``sandbox/`` stays inside the kernel boundary. The neutral
:class:`SandboxOutcome` it returns is mapped to a ``ToolResult`` by the plugin
adapter (``plugins/BaseSandboxTool.py``).
"""

from __future__ import annotations

import json
import logging
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import psutil
except ImportError:  # POSIX rlimits remain the only memory enforcement
    psutil = None

from effects.declarations import UndeclaredRequestError
from effects.interpreter import EffectContext, Interpreter, TurnJournal
from effects.vocabulary import from_wire
from sandbox.protocol import write_message
from sandbox.validate import SandboxValidationError, assert_valid

logger = logging.getLogger("Sandbox")

_ENTRY = Path(__file__).with_name("entry.py")
_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TIMEOUT_S = 30.0
DEFAULT_MEMORY_MB = 512
DEFAULT_CPU_SECONDS = 30
_POLL_INTERVAL = 0.03  # memory-watchdog sampling period (seconds)


class SandboxRunError(RuntimeError):
    """A sandboxed tool run failed at the harness level (timeout, protocol,
    validation) rather than returning an unsuccessful ``Respond``."""


@dataclass
class SandboxOutcome:
    """Neutral result of a sandbox run (mapped to ToolResult by the adapter)."""

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


def run_sandbox_tool(
    *,
    source: str,
    params: dict,
    declared: list[str],
    effect_ctx: EffectContext,
    timeout: float = DEFAULT_TIMEOUT_S,
    memory_mb: int = DEFAULT_MEMORY_MB,
    cpu_seconds: int = DEFAULT_CPU_SECONDS,
    journal: TurnJournal | None = None,
    cancel_event: threading.Event | None = None,
) -> SandboxOutcome:
    """Run one sandboxed tool. Returns a :class:`SandboxOutcome`.

    ``declared`` is the tool's declared request tags; the interpreter hard-rejects
    any undeclared request. ``journal`` may be a turn-scoped journal shared across
    tool calls so the whole turn is rolled back as one unit.
    """
    try:
        assert_valid(source)
    except SandboxValidationError as e:
        return SandboxOutcome.failed(f"validation failed: {e}", "ValidationError")

    interp = Interpreter(effect_ctx, declared, journal=journal)

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump({"code": source, "params": dict(params or {}),
                   "memory_mb": int(memory_mb), "cpu_seconds": int(cpu_seconds)}, f)
        job_path = f.name

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.Popen(
        [sys.executable, "-I", "-B", str(_ENTRY), job_path],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", cwd=str(_ROOT), env=env, bufsize=1,
    )

    lines: queue.Queue = queue.Queue()

    def _reader() -> None:
        try:
            for line in proc.stdout:  # type: ignore[union-attr]
                lines.put(line)
        finally:
            lines.put(None)  # EOF sentinel

    reader = threading.Thread(target=_reader, name="sandbox-reader", daemon=True)
    reader.start()

    # Parent-side memory watchdog: the portable enforcement of ``memory_mb``
    # (POSIX rlimits only cover Linux; Windows/macOS get nothing from the
    # child). Polls RSS of the child + descendants and kills on breach.
    mem_state = {"killed": False, "peak": 0}
    watchdog_stop = threading.Event()
    if psutil is not None:
        watchdog = threading.Thread(
            target=_memory_watchdog,
            args=(proc, int(memory_mb) * 1024 * 1024, watchdog_stop, mem_state),
            name="sandbox-mem-watchdog", daemon=True)
        watchdog.start()
    else:
        watchdog = None

    deadline = time.monotonic() + float(timeout)
    outcome: SandboxOutcome | None = None
    try:
        while True:
            if mem_state["killed"]:
                break  # outcome built below, where peak is final
            if cancel_event is not None and cancel_event.is_set():
                outcome = SandboxOutcome.failed("run cancelled", "Cancelled")
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                outcome = SandboxOutcome.failed(f"tool exceeded {timeout:.0f}s timeout", "Timeout")
                break
            try:
                line = lines.get(timeout=min(remaining, 0.5))
            except queue.Empty:
                continue
            if line is None:
                outcome = outcome or SandboxOutcome.failed("tool exited without responding", "NoRespond")
                break
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue  # stray non-protocol output (a stray print)
            # Stop the clock while the request sits on the kernel's side of
            # the pipe: fulfilment time (disk walks, and above all egress
            # gates blocked on a human approval) is not the tool's runtime.
            # The deadline only meters time the CHILD is actually computing.
            fulfil_started = time.monotonic()
            kind, outcome, done = _handle_message(message, interp, proc)
            deadline += time.monotonic() - fulfil_started
            if done:
                break
    finally:
        watchdog_stop.set()
        _terminate(proc)
        reader.join(timeout=1.0)
        if watchdog is not None:
            watchdog.join(timeout=1.0)
        try:
            os.unlink(job_path)
        except OSError:
            pass

    if mem_state["killed"]:
        peak_mb = mem_state["peak"] / (1024 * 1024)
        outcome = SandboxOutcome.failed(
            f"tool exceeded {memory_mb} MB memory cap (peak ~{peak_mb:.0f} MB)", "MemoryCap")
    if outcome is None:
        stderr = (proc.stderr.read() if proc.stderr else "") or ""
        outcome = SandboxOutcome.failed(stderr.strip()[-500:] or "unknown sandbox failure", "SandboxFailure")
    return outcome


def _memory_watchdog(proc, cap_bytes: int, stop: threading.Event, state: dict) -> None:
    """Poll the child's RSS (including descendants); kill on cap breach.

    Ported from Art's technique runner. Best-effort: an unreadable process
    (already exited) just ends the watch.

    The loop samples BEFORE it waits, and waits only briefly: a tool that
    allocates and exits can live for well under a coarse poll interval, so a
    ``wait``-first loop would never sample it. Polling is still sampling — a
    burst that allocates and frees inside one interval can slip through — but at
    ``_POLL_INTERVAL`` a sustained or even momentary over-cap is caught reliably
    (the child's own spawn/import time keeps it alive across several samples).
    """
    try:
        p = psutil.Process(proc.pid)
    except Exception:  # noqa: BLE001
        return
    while True:
        try:
            rss = p.memory_info().rss
            for child in p.children(recursive=True):
                try:
                    rss += child.memory_info().rss
                except psutil.Error:
                    pass
        except psutil.Error:
            return  # child gone
        if rss > state["peak"]:
            state["peak"] = rss
        if rss > cap_bytes:
            state["killed"] = True
            try:
                proc.kill()
            except OSError:
                pass
            return
        if stop.wait(_POLL_INTERVAL):
            return


def _handle_message(message: dict, interp: Interpreter, proc) -> tuple[str, SandboxOutcome | None, bool]:
    """Process one child→parent message. Returns (kind, outcome, done)."""
    if "yield" in message:
        try:
            request = from_wire(message["yield"])
        except (KeyError, TypeError) as e:
            _terminate(proc)
            return "yield", SandboxOutcome.failed(f"malformed request off the pipe: {e}", "ProtocolError"), True
        try:
            result = interp.fulfill(request)
        except UndeclaredRequestError as e:
            _terminate(proc)
            return "yield", SandboxOutcome.failed(str(e), "UndeclaredRequest"), True
        write_message(proc.stdin, {"resume": result.to_wire()})
        return "yield", None, False

    if "final" in message:
        return "final", _outcome_from_respond(message["final"]), True

    if "error" in message:
        diag = message["error"] or {}
        return "error", SandboxOutcome.failed(
            diag.get("message") or "tool raised", diag.get("error_type") or "ToolError"), True

    return "unknown", None, False


def _outcome_from_respond(wire: dict) -> SandboxOutcome:
    """Map a Respond wire dict to a SandboxOutcome."""
    wire = wire or {}
    return SandboxOutcome(
        success=bool(wire.get("success", True)),
        summary=wire.get("summary") or "",
        data=wire.get("data"),
        error=wire.get("error") or "",
        attachment_paths=list(wire.get("attachment_paths") or []),
    )


def _terminate(proc) -> None:
    """Kill the child if it is still running (best-effort)."""
    if proc.poll() is None:
        try:
            proc.kill()
        except OSError:
            pass
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if stream:
                stream.close()
        except OSError:
            pass

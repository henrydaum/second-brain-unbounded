"""Resident sandbox workers — a child that stays alive across calls.

``runner.py`` spawns a child per call: maximally isolated, and the right default
for tools, but it costs ~520 ms (dominated by the child's imports, not spawn) and
it has nowhere to put state. A plugin that wants a cache, a connection, or a
background thread cannot exist under it.

A worker keeps one child alive with **one plugin instance** constructed once, so:

- state between calls lives in the child, which is what makes threads and
  long-lived services sandboxable at all;
- every call after the first skips the import cost.

**The trade, stated plainly.** A resident worker is less isolated than a fresh
one: whatever a call leaves behind — a poisoned cache, a mutated attribute — is
still there for the next call. Per-call spawn kills that at the end of every
call. So workers are recycled after ``MAX_CALLS`` and can be recycled on demand,
and tools stay on per-call spawn by default, where the isolation is stronger and
520 ms is affordable.

What does *not* relax: every call builds a fresh :class:`Interpreter`, so
declarations, tiers, argument checks and taint are per-call. Residency changes
where the plugin's own state lives, never what it is allowed to do.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

try:
    import psutil
except ImportError:  # POSIX rlimits remain the only memory enforcement
    psutil = None

from effects.declarations import UndeclaredRequestError
from effects.interpreter import EffectContext, Interpreter, TurnJournal
from sandbox.driver import SandboxOutcome
from sandbox.protocol import read_message, write_message
from sandbox.runner import _handle_message, _memory_watchdog, _terminate
from sandbox.validate import SandboxValidationError, assert_valid

logger = logging.getLogger("Sandbox.worker")

_ENTRY = Path(__file__).with_name("entry.py")
_ROOT = Path(__file__).resolve().parents[1]

# Calls an *ephemeral* worker serves before it is retired and respawned. Bounds
# how far any state a call leaves behind can travel.
MAX_CALLS = 50
# Idle *ephemeral* workers are cheap (~4 MB) but not free.
MAX_IDLE_S = 600.0


class SandboxWorker:
    """One resident child serving repeated calls for a single plugin source.

    Two lifetimes, because they want opposite things:

    - **ephemeral** (``persistent=False``) — a warm cache for tools and commands.
      State surviving between calls is an unwanted side effect here, so the
      worker is retired after ``MAX_CALLS`` or ``MAX_IDLE_S``, bounding how far
      anything a call leaves behind can travel.
    - **persistent** (``persistent=True``) — a *service*. Here the surviving
      state is the entire point: a service holds caches, connections, and
      background threads, and recycling it would destroy exactly what makes it a
      service rather than a function. Its lifetime is the service's own —
      created at load, closed at unload — and neither call count nor idleness
      retires it.

    A wedged call still kills the child in both cases: a worker stuck mid-request
    cannot be trusted to serve the next one. A persistent service simply loses
    its state and starts fresh, which is the same thing a crash would do.
    """

    def __init__(self, *, source: str, memory_mb: int = 512, cpu_seconds: int = 30,
                 start_timeout: float = 30.0, persistent: bool = False,
                 modules: dict[str, str] | None = None):
        """Validate the source and its closure, spawn the child, wait for ready."""
        modules = dict(modules or {})
        assert_valid(source)
        for text in modules.values():
            assert_valid(text)          # a helper is held to the plugin's standard
        self.source = source
        self.modules = modules
        self.memory_mb = int(memory_mb)
        self.persistent = bool(persistent)
        self.calls = 0
        self.last_used = time.monotonic()
        self._lock = threading.Lock()
        self._mem_state = {"killed": False, "peak": 0}
        self._watchdog_stop = threading.Event()

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump({"code": source, "params": {}, "resident": True,
                       "modules": modules,
                       "memory_mb": self.memory_mb, "cpu_seconds": int(cpu_seconds)}, f)
            self._job_path = f.name

        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        self.proc = subprocess.Popen(
            [sys.executable, "-I", "-B", str(_ENTRY), self._job_path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", cwd=str(_ROOT), env=env, bufsize=1,
        )

        self._lines: queue.Queue = queue.Queue()
        self._reader = threading.Thread(target=self._read_loop, name="worker-reader", daemon=True)
        self._reader.start()

        if psutil is not None:
            threading.Thread(
                target=_memory_watchdog,
                args=(self.proc, self.memory_mb * 1024 * 1024,
                      self._watchdog_stop, self._mem_state),
                name="worker-mem-watchdog", daemon=True).start()

        if not self._await_ready(start_timeout):
            stderr = (self.proc.stderr.read() if self.proc.stderr else "") or ""
            self.close()
            raise RuntimeError(f"sandbox worker failed to start: {stderr.strip()[-500:]}")

    # ── lifecycle ────────────────────────────────────────────────────────

    def _read_loop(self) -> None:
        """Pump the child's stdout into a queue (Windows pipes have no select)."""
        try:
            for line in self.proc.stdout:  # type: ignore[union-attr]
                self._lines.put(line)
        finally:
            self._lines.put(None)

    def _await_ready(self, timeout: float) -> bool:
        """Block until the child reports it has constructed the plugin."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = self._lines.get(timeout=0.25)
            except queue.Empty:
                continue
            if line is None:
                return False
            try:
                if json.loads(line).get("ready"):
                    return True
            except json.JSONDecodeError:
                continue  # stray print during import
        return False

    @property
    def alive(self) -> bool:
        """Whether the child can serve another call.

        A persistent (service) worker is not subject to the call budget: its
        state is the point, and retiring it mid-life would drop caches,
        connections and threads the service is expected to keep."""
        running = self.proc.poll() is None and not self._mem_state["killed"]
        if self.persistent:
            return running
        return running and self.calls < MAX_CALLS

    def close(self) -> None:
        """Shut the child down, politely then firmly."""
        self._watchdog_stop.set()
        try:
            if self.proc.poll() is None and self.proc.stdin:
                write_message(self.proc.stdin, {"shutdown": True})
                self.proc.wait(timeout=2.0)
        except Exception:  # noqa: BLE001 — best-effort; _terminate is the backstop
            pass
        _terminate(self.proc)
        try:
            os.unlink(self._job_path)
        except OSError:
            pass

    # ── calling ──────────────────────────────────────────────────────────

    def call(self, *, params: dict, declared: list[str], effect_ctx: EffectContext,
             method: str = "run", timeout: float = 30.0,
             journal: TurnJournal | None = None,
             cancel_event: threading.Event | None = None) -> SandboxOutcome:
        """Serve one call on this worker. Returns a :class:`SandboxOutcome`.

        A fresh interpreter per call: residency is about where the *plugin's*
        state lives, not about relaxing what it may do."""
        interp = Interpreter(effect_ctx, declared, journal=journal)
        with self._lock:
            self.calls += 1
            self.last_used = time.monotonic()
            if self.proc.poll() is not None:
                return SandboxOutcome.failed("sandbox worker is not running", "WorkerDead")
            try:
                write_message(self.proc.stdin, {
                    "job": {"params": dict(params or {}), "method": method}})
            except OSError as e:
                return SandboxOutcome.failed(f"could not reach the worker: {e}", "WorkerDead")
            return self._pump(interp, timeout, cancel_event)

    def _pump(self, interp: Interpreter, timeout: float,
              cancel_event: threading.Event | None) -> SandboxOutcome:
        """Fulfil requests until the child reports a final result.

        The deadline meters only time the *child* is computing: it is extended
        by however long each fulfilment sits on the kernel's side, because an
        egress gate blocked on a human is not the plugin being slow."""
        deadline = time.monotonic() + float(timeout)
        outcome: SandboxOutcome | None = None
        while True:
            if self._mem_state["killed"]:
                peak_mb = self._mem_state["peak"] / (1024 * 1024)
                return SandboxOutcome.failed(
                    f"worker exceeded {self.memory_mb} MB memory cap (peak ~{peak_mb:.0f} MB)",
                    "MemoryCap")
            if cancel_event is not None and cancel_event.is_set():
                return SandboxOutcome.failed("run cancelled", "Cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # A wedged call poisons the worker: it may still be mid-request,
                # so the child is retired rather than reused.
                self.close()
                return SandboxOutcome.failed(f"call exceeded {timeout:.0f}s timeout", "Timeout")
            try:
                line = self._lines.get(timeout=min(remaining, 0.5))
            except queue.Empty:
                continue
            if line is None:
                return SandboxOutcome.failed("worker exited without responding", "NoRespond")
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue  # stray non-protocol output
            fulfil_started = time.monotonic()
            try:
                _kind, outcome, done = _handle_message(message, interp, self.proc)
            except UndeclaredRequestError as e:
                self.close()
                return SandboxOutcome.failed(str(e), "UndeclaredRequest")
            deadline += time.monotonic() - fulfil_started
            if done:
                return outcome or SandboxOutcome.failed("no result", "SandboxFailure")


class WorkerPool:
    """Resident workers, keyed by plugin source.

    Keyed by a hash of the source rather than by name: a worker has already
    exec'd its code, so a changed plugin must not be served by the old child.
    Editing a file therefore retires its worker for free, which is also what
    keeps the trust model honest (an edit drops a plugin back to untrusted).
    """

    def __init__(self, max_workers: int = 8):
        """Create an empty pool."""
        self._workers: dict[str, SandboxWorker] = {}
        self._lock = threading.Lock()
        self.max_workers = max_workers

    @staticmethod
    def _key(source: str, modules: dict[str, str] | None = None) -> str:
        """Content address for a plugin — its entry file *and* its closure.

        Keying on the entry file alone would hand back a stale worker after a
        helper was edited: the plugin's own bytes are unchanged, but what it
        runs is not."""
        digest = hashlib.sha256(source.encode("utf-8"))
        for name in sorted(modules or {}):
            digest.update(b"\0")
            digest.update(name.encode("utf-8"))
            digest.update(b"\0")
            digest.update((modules or {})[name].encode("utf-8"))
        return digest.hexdigest()

    def acquire(self, *, source: str, memory_mb: int = 512, cpu_seconds: int = 30,
                persistent: bool = False,
                modules: dict[str, str] | None = None) -> SandboxWorker:
        """Return a live worker for ``source``, spawning or recycling as needed.

        ``persistent=True`` marks a service worker: exempt from the call budget,
        the idle reaper, and eviction under pressure, because its state is the
        capability rather than an artifact of it."""
        key = self._key(source, modules)
        with self._lock:
            self._reap()
            worker = self._workers.get(key)
            if worker is not None and worker.alive:
                return worker
            if worker is not None:
                worker.close()
                self._workers.pop(key, None)
            if len(self._workers) >= self.max_workers:
                self._evict_one()
            worker = SandboxWorker(source=source, memory_mb=memory_mb,
                                   cpu_seconds=cpu_seconds, persistent=persistent,
                                   modules=modules)
            self._workers[key] = worker
            return worker

    def _evict_one(self) -> None:
        """Make room by closing the least recently used *ephemeral* worker.

        Persistent workers are never evicted for capacity: dropping a live
        service to make room for a tool call would trade a durable capability
        for a transient one. If only persistent workers remain, the pool is
        allowed to exceed ``max_workers`` rather than break a service."""
        candidates = {k: w for k, w in self._workers.items() if not w.persistent}
        if not candidates:
            logger.debug("worker pool over capacity but all workers are persistent")
            return
        key = min(candidates, key=lambda k: candidates[k].last_used)
        self._workers[key].close()
        self._workers.pop(key, None)

    def _reap(self) -> None:
        """Drop workers that died, hit their call budget, or went idle.

        Idleness never retires a persistent worker — a service that has not been
        called in ten minutes is idle, not finished, and its threads may well be
        the reason it exists."""
        now = time.monotonic()
        for key, worker in list(self._workers.items()):
            if not worker.alive:
                worker.close()
                self._workers.pop(key, None)
            elif not worker.persistent and (now - worker.last_used) > MAX_IDLE_S:
                worker.close()
                self._workers.pop(key, None)

    def release(self, source: str, modules: dict[str, str] | None = None) -> None:
        """Close the worker for ``source`` — a service's unload path."""
        key = self._key(source, modules)
        with self._lock:
            worker = self._workers.pop(key, None)
        if worker is not None:
            worker.close()

    def shutdown(self) -> None:
        """Close every worker (kernel shutdown)."""
        with self._lock:
            for worker in self._workers.values():
                worker.close()
            self._workers.clear()


# The kernel's pool. Module-level so a plugin's worker survives across calls;
# closed by the runtime at shutdown.
POOL = WorkerPool()

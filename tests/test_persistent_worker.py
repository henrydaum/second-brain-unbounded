"""Resident workers — a sandbox that stays open across calls.

Two lifetimes with opposite goals, which is the whole design:

- **ephemeral**: a warm cache for tools. State surviving between calls is an
  unwanted side effect, so the worker is retired on a budget.
- **persistent**: a *service*. The surviving state is the capability — caches,
  connections, background threads — so nothing but unload or death retires it.

These tests spawn real subprocesses, so they are slower than the rest of the
suite; they are the only way to prove the state actually crosses calls.
"""

from __future__ import annotations

import pytest

from effects.interpreter import EffectContext
from sandbox.worker import MAX_CALLS, SandboxWorker, WorkerPool

# A plugin that counts its own calls in instance state. If the child is
# reconstructed between calls the counter resets, which is exactly the thing
# under test.
COUNTER_SOURCE = '''
from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import Respond


class Counter(BaseSandboxTool):
    name = "counter"
    description = "counts calls in resident state"
    declared_requests = []

    def __init__(self):
        self.seen = 0

    def run(self, params):
        self.seen += 1
        return Respond(summary=str(self.seen), data=self.seen)
        yield  # noqa — makes run a generator
'''


@pytest.fixture
def worker():
    """A persistent worker, closed after the test."""
    w = SandboxWorker(source=COUNTER_SOURCE, persistent=True)
    yield w
    w.close()


def _call(worker, **kw):
    """One call with an empty effect context."""
    return worker.call(params={}, declared=[], effect_ctx=EffectContext(tool_name="counter"),
                       timeout=20, **kw)


# ── state survives ───────────────────────────────────────────────────────

def test_instance_state_survives_across_calls(worker):
    """The headline property: one instance, constructed once, reused.

    Without this a service cannot hold a cache, a connection, or a thread, and
    the always-trusted exception for those capabilities would be permanent."""
    assert [_call(worker).data for _ in range(3)] == [1, 2, 3]


def test_a_fresh_worker_starts_clean():
    """Residency is per-worker, not global — a new child has new state."""
    first = SandboxWorker(source=COUNTER_SOURCE, persistent=True)
    try:
        assert _call(first).data == 1
    finally:
        first.close()

    second = SandboxWorker(source=COUNTER_SOURCE, persistent=True)
    try:
        assert _call(second).data == 1
    finally:
        second.close()


def test_the_boundary_still_applies_to_a_resident_worker(worker):
    """Residency changes where the plugin's state lives, never what it may do:
    an undeclared request is still a hard reject."""
    source = COUNTER_SOURCE.replace(
        "        self.seen += 1\n        return Respond(summary=str(self.seen), data=self.seen)\n        yield  # noqa — makes run a generator",
        "        yield ReadFile(path='x')\n        return Respond(summary='unreachable')"
    ).replace("from effects.vocabulary import Respond",
              "from effects.vocabulary import ReadFile, Respond")
    w = SandboxWorker(source=source, persistent=True)
    try:
        outcome = w.call(params={}, declared=[], effect_ctx=EffectContext(tool_name="c"),
                         timeout=20)
        assert not outcome.success
        assert outcome.error_type == "UndeclaredRequest"
    finally:
        w.close()


# ── the two lifetimes ────────────────────────────────────────────────────

def test_a_persistent_worker_ignores_the_call_budget(worker):
    """A service must not be retired mid-life: dropping its state at call 50
    would destroy the very thing that makes it a service."""
    worker.calls = MAX_CALLS + 10

    assert worker.alive
    assert _call(worker).success


def test_an_ephemeral_worker_retires_on_the_call_budget():
    """A tool's warm worker is bounded, so anything a call leaves behind cannot
    travel far."""
    w = SandboxWorker(source=COUNTER_SOURCE, persistent=False)
    try:
        assert w.alive
        w.calls = MAX_CALLS
        assert not w.alive
    finally:
        w.close()


def test_a_dead_child_is_not_alive_even_when_persistent(worker):
    """Persistence exempts a worker from the budget, never from reality."""
    worker.proc.kill()
    worker.proc.wait(timeout=5)

    assert not worker.alive


# ── pool behaviour ───────────────────────────────────────────────────────

def test_the_pool_reuses_a_worker_for_identical_source():
    """Same source, same child — that is what makes the second call cheap."""
    pool = WorkerPool()
    try:
        first = pool.acquire(source=COUNTER_SOURCE, persistent=True)
        second = pool.acquire(source=COUNTER_SOURCE, persistent=True)
        assert first is second
        assert _call(first).data == 1
        assert _call(second).data == 2      # …and the state is shared, being one child
    finally:
        pool.shutdown()


def test_editing_the_source_retires_the_worker():
    """The pool is keyed by content, so a changed plugin is never served by a
    child that already exec'd the old code. This is also what keeps the trust
    model honest — an edit drops a plugin back to untrusted."""
    pool = WorkerPool()
    try:
        first = pool.acquire(source=COUNTER_SOURCE, persistent=True)
        edited = COUNTER_SOURCE.replace('description = "counts calls in resident state"',
                                        'description = "edited"')
        second = pool.acquire(source=edited, persistent=True)
        assert first is not second
    finally:
        pool.shutdown()


def test_capacity_pressure_never_evicts_a_service():
    """Dropping a live service to make room for a tool call would trade a
    durable capability for a transient one, so the pool exceeds its size
    instead."""
    pool = WorkerPool(max_workers=1)
    try:
        service = pool.acquire(source=COUNTER_SOURCE, persistent=True)
        other = pool.acquire(
            source=COUNTER_SOURCE.replace('name = "counter"', 'name = "other"'),
            persistent=True)

        assert service.alive
        assert other.alive
        assert _call(service).success        # the first service still works
    finally:
        pool.shutdown()


def test_release_closes_a_service_worker():
    """A service's unload path must actually stop the child."""
    pool = WorkerPool()
    try:
        worker = pool.acquire(source=COUNTER_SOURCE, persistent=True)
        pool.release(COUNTER_SOURCE)

        assert worker.proc.poll() is not None
    finally:
        pool.shutdown()

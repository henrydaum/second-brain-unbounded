"""Periodic work without a thread — retiring the "owns a thread" exception.

A generator cannot act between calls: it yields when driven, and nothing drives
it while it waits. That is why "owns a thread or event loop" looked like it could
never be sandboxed.

The inversion: the kernel owns one thread and *ticks* the service, and the
service returns the events it wants fired rather than firing them. Both halves
matter —

- being ticked means no plugin thread, so the capability disappears rather than
  being mediated;
- returning events means the kernel checks them against ``declared_channels``,
  which is to the bus what ``declared_requests`` is to the interpreter.

An ``Emit`` request would not have worked: the kernel cannot journal a fired
event and bus subscribers run immediately, so by the tier rules it would be
egress — an approval on every tick, which is no scheduler at all.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

from events.event_bus import bus
from runtime.service_ticker import MIN_INTERVAL_S, ServiceTicker, channel_danger_tier


class _Ticked:
    """A stand-in service recording how it was called."""

    loaded = True
    tick_interval_s = 0.01           # below the floor on purpose
    declared_channels = ["jobs.fired"]

    def __init__(self, events=None):
        self.calls = []
        self._events = events if events is not None else [
            {"channel": "jobs.fired", "payload": {"job": "nightly"}}]

    def perform(self, method, params, context):
        self.calls.append((method, params, context))
        return self._events


def _ticker(service, **kw):
    return ServiceTicker({"ticked": service}, lambda name: SimpleNamespace(name=name), **kw)


def _capture(channel):
    """Subscribe and return (received, unsubscribe)."""
    got = []
    unsub = bus.subscribe(channel, got.append)
    return got, unsub


# ── being ticked ─────────────────────────────────────────────────────────

def test_a_service_is_ticked_without_owning_a_thread():
    """The whole point: periodic work with no plugin-side loop."""
    service = _Ticked()
    ticker = _ticker(service, poll_interval_s=0.01)
    ticker.start()
    try:
        deadline = time.monotonic() + 3.0
        while not service.calls and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        ticker.stop()

    assert service.calls, "the service was never ticked"
    method, params, context = service.calls[0]
    assert method == "tick"
    assert params == {}
    assert context.name == "ticked"     # a context, never the runtime


def test_a_service_that_asks_for_no_tick_is_never_ticked():
    """Ticking is opt-in; the default costs nothing."""
    service = _Ticked()
    service.tick_interval_s = 0
    ticker = _ticker(service, poll_interval_s=0.01)
    ticker.start()
    try:
        time.sleep(0.2)
    finally:
        ticker.stop()

    assert service.calls == []


def test_an_unloaded_service_is_not_ticked():
    """A service that failed to load has no business doing periodic work."""
    service = _Ticked()
    service.loaded = False
    ticker = _ticker(service, poll_interval_s=0.01)
    ticker.start()
    try:
        time.sleep(0.2)
    finally:
        ticker.stop()

    assert service.calls == []


def test_the_tick_interval_has_a_floor():
    """A plugin must not be able to busy-spin the kernel's clock by declaring a
    tiny interval."""
    service = _Ticked()          # declares 0.01s
    ticker = _ticker(service, poll_interval_s=0.01)
    ticker.start()
    try:
        time.sleep(MIN_INTERVAL_S * 1.4)
    finally:
        ticker.stop()

    # Without the floor this would be ~70 ticks.
    assert len(service.calls) <= 3, f"floor not applied: {len(service.calls)} ticks"


# ── the authority check ──────────────────────────────────────────────────

def test_declared_channels_are_emitted():
    """The kernel fires what the tick returned."""
    got, unsub = _capture("jobs.fired")
    service = _Ticked()
    ticker = _ticker(service, poll_interval_s=0.01)
    ticker.start()
    try:
        deadline = time.monotonic() + 3.0
        while not got and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        ticker.stop()
        unsub()

    assert got and got[0] == {"job": "nightly"}


def test_an_undeclared_channel_is_refused():
    """Declaring a channel is to the bus what declaring a request type is to the
    interpreter — a service cannot reach a channel it did not declare."""
    got, unsub = _capture("secret.channel")
    service = _Ticked(events=[{"channel": "secret.channel", "payload": {"x": 1}}])
    ticker = _ticker(service, poll_interval_s=0.01)
    ticker.start()
    try:
        time.sleep(MIN_INTERVAL_S * 1.6)
    finally:
        ticker.stop()
        unsub()

    assert service.calls, "precondition: the service should have been ticked"
    assert got == []


def test_a_malformed_event_list_is_ignored():
    """The payload crosses a boundary from untrusted code, so it is validated
    rather than believed."""
    service = _Ticked(events=["not a dict", {"no_channel": True}, 42])
    ticker = _ticker(service, poll_interval_s=0.01)
    ticker.start()
    try:
        time.sleep(MIN_INTERVAL_S * 1.6)
    finally:
        ticker.stop()

    assert service.calls  # survived without raising


# ── containment ──────────────────────────────────────────────────────────

def test_a_raising_service_does_not_stop_the_clock():
    """One broken service must not stop every other service's periodic work."""

    class _Broken(_Ticked):
        def perform(self, method, params, context):
            self.calls.append((method, params, context))
            raise RuntimeError("boom")

    broken, healthy = _Broken(), _Ticked()
    ticker = ServiceTicker({"broken": broken, "healthy": healthy},
                           lambda name: SimpleNamespace(name=name),
                           poll_interval_s=0.01)
    ticker.start()
    try:
        deadline = time.monotonic() + 3.0
        while not (broken.calls and healthy.calls) and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        ticker.stop()

    assert broken.calls, "the broken service should have been tried"
    assert healthy.calls, "a raising service stopped the clock for others"


# ── the tier of an emit is derived from what it triggers ─────────────────
#
# Emitting is not dangerous in itself; it is dangerous in proportion to what
# listens. So the tier is computed from the subscribed tasks' own derived tiers
# rather than asserted about the channel -- "derive, never assert", applied
# transitively.

def _task(name, channels, declared, emits=None):
    from plugins.BaseTask import BaseTask

    cls = type(f"_T{name}", (BaseTask,), {
        "contract": "effects", "name": name,
        "trigger_channels": list(channels),
        "declared_requests": list(declared),
        "declared_channels": list(emits or []),
    })
    return cls()


def test_a_channel_with_no_subscribers_is_read_tier():
    """Nothing listens, so nothing happens."""
    assert channel_danger_tier("quiet", {}) == "read"


def test_a_channel_is_as_dangerous_as_its_most_dangerous_subscriber():
    """One read-only listener and one that writes makes the emit a write."""
    tasks = {
        "reader": _task("reader", ["work"], ["read_file"]),
        "writer": _task("writer", ["work"], ["write_file"]),
    }

    assert channel_danger_tier("work", tasks) == "write"


def test_a_channel_reaching_egress_is_egress():
    """A task that posts to an API makes firing its channel irreversible."""
    tasks = {"poster": _task("poster", ["work"], ["http_request"])}

    assert channel_danger_tier("work", tasks) == "egress"


def test_danger_is_traced_through_a_chain_of_emits():
    """A task that itself emits extends the blast radius, so the walk follows
    it: an apparently harmless channel is egress if it eventually reaches one."""
    tasks = {
        "first": _task("first", ["start"], ["read_file"], emits=["second"]),
        "sender": _task("sender", ["second"], ["http_request"]),
    }

    assert channel_danger_tier("start", tasks) == "egress"


def test_a_cycle_does_not_recurse_forever():
    """A triggers B triggers A resolves to the highest tier found, not a hang."""
    tasks = {
        "a": _task("a", ["ping"], ["read_file"], emits=["pong"]),
        "b": _task("b", ["pong"], ["write_file"], emits=["ping"]),
    }

    assert channel_danger_tier("ping", tasks) == "write"


def test_a_dangerous_emit_is_gated():
    """Egress-tier emits route through approval, naming what they trigger."""
    asked = []
    tasks = {"poster": _task("poster", ["jobs.fired"], ["http_request"])}
    got, unsub = _capture("jobs.fired")
    service = _Ticked()
    ticker = ServiceTicker({"ticked": service}, lambda n: SimpleNamespace(name=n),
                           poll_interval_s=0.01, tasks=tasks,
                           approve=lambda t, j: asked.append((t, j)) or False)
    ticker.start()
    try:
        time.sleep(MIN_INTERVAL_S * 1.6)
    finally:
        ticker.stop()
        unsub()

    assert asked, "an egress-tier emit was not gated"
    assert "jobs.fired" in asked[0][0]
    assert "poster" in asked[0][1]
    assert got == [], "a denied emit still fired"


def test_a_harmless_emit_is_not_gated():
    """A channel whose subscribers only read fires silently -- the control is
    proportional, not a blanket tax on scheduling."""
    asked = []
    tasks = {"reader": _task("reader", ["jobs.fired"], ["read_file"])}
    got, unsub = _capture("jobs.fired")
    service = _Ticked()
    ticker = ServiceTicker({"ticked": service}, lambda n: SimpleNamespace(name=n),
                           poll_interval_s=0.01, tasks=tasks,
                           approve=lambda t, j: asked.append((t, j)) or True)
    ticker.start()
    try:
        deadline = time.monotonic() + 3.0
        while not got and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        ticker.stop()
        unsub()

    assert got, "a harmless emit did not fire"
    assert asked == [], "a harmless emit was gated"

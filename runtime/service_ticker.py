"""The kernel's clock for services — so a service never needs a thread of its own.

"Owns a thread or event loop" used to be one of the capabilities that forced the
always-trusted exception, because a generator has no way to act between calls:
it yields when driven, and nothing drives it while it waits.

The fix is to invert it. A service does not run a loop; it *is ticked* — the
kernel owns one thread, calls ``tick`` on each service that asked for one, and
the service does its periodic work as an ordinary body over typed requests.

**The service does not emit; it returns what it wants emitted.** This is the same
inversion as a command returning a form spec rather than live ``FormStep``s, and
it matters for the same reason: an ``Emit`` request would have to be egress tier
(the kernel cannot journal a fired event, and bus handlers run immediately), so a
scheduler would need an approval on every fire — unusable. Returning the events
instead lets the kernel apply policy at the boundary: it fires only channels the
service declared, so authority is checked once at declaration rather than
per tick.

One thread total, not one per service: a hundred ticked services cost one thread.
"""

from __future__ import annotations

import logging
import threading
import time

from events.event_bus import bus

logger = logging.getLogger("ServiceTicker")

# Floor on how often any service can be ticked, so a plugin cannot busy-spin the
# kernel's clock by declaring a tiny interval.
MIN_INTERVAL_S = 0.5
# How long a single tick may take before it is abandoned. A slow tick delays
# only itself; the ticker thread moves on.
TICK_TIMEOUT_S = 30.0


class ServiceTicker:
    """Calls ``tick`` on services that asked to be ticked, on one shared thread."""

    def __init__(self, services: dict, context_factory, poll_interval_s: float = 0.5):
        """Bind to the live service registry and a factory for call contexts."""
        self._services = services
        self._context_factory = context_factory
        self._poll_interval_s = poll_interval_s
        self._due: dict[str, float] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ── lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        """Begin ticking. Idempotent."""
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="ServiceTicker", daemon=True)
        self._thread.start()
        logger.debug("service ticker started")

    def stop(self) -> None:
        """Stop ticking and wait briefly for the thread to finish."""
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=5.0)

    # ── the loop ─────────────────────────────────────────────────────────

    def _loop(self) -> None:
        """Poll for due services until stopped. Never dies on a bad tick."""
        while not self._stop.wait(self._poll_interval_s):
            try:
                self._tick_due()
            except Exception:  # noqa: BLE001 — the clock must outlive any one service
                logger.exception("service tick sweep failed")

    def _tick_due(self) -> None:
        """Tick every loaded service whose interval has elapsed."""
        now = time.monotonic()
        for name, service in list(self._services.items()):
            interval = float(getattr(service, "tick_interval_s", 0) or 0)
            if interval <= 0 or not getattr(service, "loaded", False):
                continue
            interval = max(interval, MIN_INTERVAL_S)
            if now < self._due.get(name, 0.0):
                continue
            self._due[name] = now + interval
            self._tick_one(name, service)

    def _tick_one(self, name: str, service) -> None:
        """Tick one service and fire whatever it asked for.

        A raising or slow tick is contained: it is logged and the sweep
        continues, because one broken service must not stop the kernel's clock.
        """
        try:
            events = service.perform("tick", {}, self._context_factory(name))
        except Exception:  # noqa: BLE001 — a service's fault, not the clock's
            logger.exception("service %r tick failed", name)
            return
        self._emit(name, service, events)

    def _emit(self, name: str, service, events) -> None:
        """Fire the events a tick returned, confined to declared channels.

        This is the authority check. The service never touches the bus, so the
        only channels it can reach are the ones it declared — checked here, at
        the boundary, exactly like a declared request type."""
        if not events:
            return
        if isinstance(events, dict):
            events = [events]
        if not isinstance(events, list):
            logger.warning("service %r tick returned %s, expected a list", name, type(events).__name__)
            return
        allowed = set(getattr(service, "declared_channels", []) or [])
        for event in events:
            if not isinstance(event, dict):
                logger.warning("service %r returned a malformed event: %r", name, event)
                continue
            channel = event.get("channel")
            if not channel:
                continue
            if channel not in allowed:
                logger.warning(
                    "service %r tried to emit on undeclared channel %r; declared: %s",
                    name, channel, sorted(allowed) or "none")
                continue
            try:
                bus.emit(channel, event.get("payload") or {})
            except Exception:  # noqa: BLE001 — a subscriber's fault, not the ticker's
                logger.exception("emitting %r for service %r failed", channel, name)

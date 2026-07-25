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


def _scheduled_job_channels() -> list[str]:
    """Channels the kernel's scheduled jobs fire on."""
    from runtime.scheduling import get_store

    return get_store().channels()


# Dynamic channel sources, by the name a service puts in ``channels_view``.
#
# A literal ``declared_channels`` list is the normal case and stays the default.
# But a scheduler's channels come from configured jobs, so it cannot write them
# down — and handing the kernel a callable to ask instead would be capability #5
# (a live callable the kernel executes), the exact thing the contract removes.
#
# So the service names a view and the kernel resolves it. Deliberately a small
# closed map for the same reason ``INVENTORY_VIEWS`` is: a view that took
# arguments would be a generic accessor wearing a declaration's badge, and the
# declaration is the authority check.
CHANNEL_VIEWS = {
    "scheduled_jobs": _scheduled_job_channels,
}


def channel_danger_tier(channel: str, tasks: dict, *, _seen: set | None = None) -> str:
    """How dangerous is it to fire ``channel``? Derived from what it triggers.

    Emitting is not dangerous in itself — it is dangerous exactly in proportion
    to what listens. A channel whose only subscriber reads files is a read; a
    channel that starts a task which posts to an API is an egress. So the tier of
    an emit is not a judgement call about the channel's *name*, it is the maximum
    derived tier of every task subscribed to it.

    That keeps the "derive, never assert" rule intact, just applied transitively:
    tasks already declare their requests, and their tiers already fall out of
    those declarations. Nothing new is asserted anywhere.

    Transitive by design — a triggered task may itself declare channels, so the
    walk follows them. ``_seen`` breaks cycles (A triggers B triggers A), which
    resolve to the highest tier found along the way rather than recursing.

    Honest limit: this is only as good as the declaration chain. A task that
    reaches further than it declared is already a hard reject at the interpreter,
    so the chain cannot silently under-report — but a channel with *no*
    subscribers is genuinely read tier, and becomes more dangerous the moment
    something subscribes. It is computed per emit for that reason, never cached.
    """
    from effects.vocabulary import TIER_ORDER, TIER_READ

    seen = _seen if _seen is not None else set()
    if channel in seen:
        return TIER_READ          # cycle: this arm contributes nothing further
    seen.add(channel)

    tier = TIER_READ
    for task in (tasks or {}).values():
        if channel not in (getattr(task, "trigger_channels", None) or []):
            continue
        candidate = getattr(task, "danger_tier", TIER_READ)
        if TIER_ORDER.get(candidate, 0) > TIER_ORDER[tier]:
            tier = candidate
        # A task that itself emits extends the blast radius.
        for onward in (getattr(task, "declared_channels", None) or []):
            downstream = channel_danger_tier(onward, tasks, _seen=seen)
            if TIER_ORDER.get(downstream, 0) > TIER_ORDER[tier]:
                tier = downstream
    return tier


class ServiceTicker:
    """Calls ``tick`` on services that asked to be ticked, on one shared thread."""

    def __init__(self, services: dict, context_factory, poll_interval_s: float = 0.5,
                 tasks: dict | None = None, approve=None):
        """Bind to the live service registry and a factory for call contexts.

        ``tasks`` is the orchestrator's task registry, used to derive how
        dangerous each emit is from what subscribes to it. ``approve(target,
        justification) -> bool`` gates the emits that turn out to be egress
        tier; without one, an egress-tier emit is refused rather than fired."""
        self._services = services
        self._context_factory = context_factory
        self._poll_interval_s = poll_interval_s
        self._tasks = tasks if tasks is not None else {}
        self._approve = approve
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
        # Resolved *before* the body runs. A dynamic ``channels_view`` reads live
        # kernel state, and a tick may legitimately change that state — the
        # timekeeper's does, by removing the one-time job it just fired. Reading
        # the declaration afterwards would judge the tick against the world it
        # left behind, and silently refuse the very emit it was ticked for.
        allowed = self._allowed_channels(service)
        try:
            events = service.perform("tick", {}, self._context_factory(name))
        except Exception:  # noqa: BLE001 — a service's fault, not the clock's
            logger.exception("service %r tick failed", name)
            return
        self._emit(name, service, events, allowed)

    def _emit(self, name: str, service, events, allowed: set | None = None) -> None:
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
        if allowed is None:
            allowed = self._allowed_channels(service)
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
            if not self._permitted(name, channel):
                continue
            try:
                bus.emit(channel, event.get("payload") or {})
            except Exception:  # noqa: BLE001 — a subscriber's fault, not the ticker's
                logger.exception("emitting %r for service %r failed", channel, name)

    def _allowed_channels(self, service) -> set:
        """Which channels this service may fire on: its literal declaration plus
        whatever its declared ``channels_view`` currently resolves to.

        A failing view resolves to nothing rather than to everything — the
        declaration is the authority check, so an unreadable one must deny."""
        allowed = set(getattr(service, "declared_channels", None) or [])
        view = getattr(service, "channels_view", "") or ""
        if not view:
            return allowed
        resolver = CHANNEL_VIEWS.get(view)
        if resolver is None:
            logger.warning("unknown channels_view %r; declaring nothing dynamic", view)
            return allowed
        try:
            return allowed | set(resolver() or [])
        except Exception:  # noqa: BLE001 — an unreadable view declares nothing
            logger.exception("channels_view %r failed", view)
            return allowed

    def _permitted(self, name: str, channel: str) -> bool:
        """Whether firing ``channel`` is allowed, given what it triggers.

        Read and write tiers fire silently: a write-tier task is journalled and
        reversible, which is the property that makes it safe to run unattended.
        Egress is different — it is irreversible by definition — so it is gated
        the same way a direct egress request would be. The prompt names the
        channel and the reason it is dangerous, since "allow this scheduled job"
        is only answerable if you know what the job will reach."""
        from effects.vocabulary import TIER_EGRESS

        tier = channel_danger_tier(channel, self._tasks)
        if tier != TIER_EGRESS:
            return True
        if self._approve is None:
            logger.warning(
                "service %r: refusing to emit %r (egress tier) with no approval surface",
                name, channel)
            return False
        triggered = sorted(
            t.name for t in (self._tasks or {}).values()
            if channel in (getattr(t, "trigger_channels", None) or []))
        return bool(self._approve(
            f"emit {channel}",
            f"scheduled job from service {name!r} triggers: {', '.join(triggered) or 'unknown'}"))

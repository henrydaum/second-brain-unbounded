"""Service plugin for timekeeper — the scheduler, on the effects contract.

This service used to be the clearest case for the always-trusted exception: it
owned a thread and it called ``bus.emit`` directly, which is capability #2 twice
over. Both halves have exits now, and this is the plugin walking through them.

- **The thread** belongs to ``runtime/service_ticker.py``. One kernel clock ticks
  every service that declares ``tick_interval_s``; a hundred ticked services cost
  one thread, and none of them owns a loop.
- **The bus** is never touched. ``tick`` *returns* the events it wants fired, and
  the ticker fires only channels this service declared — then grades each one by
  what subscribes to it (``channel_danger_tier``) and gates the egress ones.
- **The job table** belongs to ``runtime/scheduling.py``. Cron arithmetic is
  infrastructure (a sandboxed body cannot import ``croniter``, and widening the
  import gate for one plugin would make the conversion cosmetic), and the table
  is read by the orchestrator and by ``/schedule`` as well as by this tick.

What is left is what was always genuinely this plugin's work: **deciding which
jobs are due right now and what payload each fired event carries**. That is date
comparison and dict building over a snapshot — pure work, which is exactly what a
sandboxed body is for. Everything the old version reached for directly, it now
names: a read for the table, a write to advance the clocks.

Note there is no job CRUD here any more, not even as a thin delegation. Keeping a
private parent-side API would have meant this file importing the kernel store,
which the sandbox import gate rejects — and rightly: a plugin with a back door
that only works in one execution mode is not converted, it is half-converted.
Callers that manage jobs use ``runtime.scheduling`` (kernel) or ``ScheduleOp``
(plugins).
"""

from plugins.BaseService import BaseService


class TimekeeperService(BaseService):
    """Fires scheduled events by cron expression or one-time datetime."""

    model_name = "Timekeeper"
    shared = True
    config_settings = [
        (
            "Scheduled Jobs",
            "scheduled_jobs",
            "JSON object keyed by job name describing scheduled event emissions.",
            {},
            {"type": "text", "hidden": True},
        ),
    ]

    contract = "effects"
    declared_requests = ["read_context", "schedule_op"]

    # Once a second, matching the old poll interval. The ticker floors this at
    # MIN_INTERVAL_S so no plugin can busy-spin the kernel's clock.
    tick_interval_s = 1.0

    # Job channels are configured, not hard-coded, so this service cannot list
    # its channels as a literal. It names the inventory view that holds them and
    # the kernel resolves it — the same "return a spec, not a live thing"
    # inversion as a command returning form dicts instead of FormSteps. The
    # authority check is unweakened: the ticker still refuses any channel not on
    # the resolved list, and still grades what remains by what it triggers.
    channels_view = "scheduled_jobs"

    def __init__(self, config: dict = None):
        """Initialize the timekeeper service.

        The config argument is accepted for the ``build_services(config)``
        convention and deliberately not kept: this service holds no job state,
        and the kernel store is bound to the live config at boot."""
        super().__init__()

    def tick(self, params):
        """Return the events whose jobs are due, and advance those jobs' clocks.

        Two requests, both cheap: read the table, then say which jobs fired.
        ``fired_at`` carries the time each job was *scheduled for* rather than
        the time this tick noticed, so a slow tick cannot drift a repeating
        schedule forward a little on every cycle."""
        from datetime import datetime

        from effects.vocabulary import ReadContext, Respond, ScheduleOp

        snapshot = yield ReadContext(view="scheduled_jobs")
        now = datetime.now().astimezone()

        events, fired_at = [], {}
        for job in (snapshot.value or []):
            if not job.get("enabled", True):
                continue
            due = job.get("next_fire_at")
            if not due:
                continue
            try:
                when = datetime.fromisoformat(due)
            except (TypeError, ValueError):
                continue
            if when > now:
                continue
            name = job.get("name") or ""
            fired_at[name] = due
            events.append({
                "channel": job.get("channel") or "",
                "payload": {
                    **dict(job.get("payload") or {}),
                    "_timekeeper": {
                        "job_name": name,
                        "scheduled_for": due,
                        "emitted_at": now.isoformat(),
                        "one_time": bool(job.get("one_time")),
                        "source": "timekeeper",
                    },
                },
            })

        if fired_at:
            yield ScheduleOp(action="advance", names=list(fired_at), fired_at=fired_at)
        return Respond(data=events)


def build_services(config: dict) -> dict:
    """Build services."""
    return {"timekeeper": TimekeeperService(config)}

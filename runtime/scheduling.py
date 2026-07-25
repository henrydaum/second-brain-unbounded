"""The kernel's job store — cron state, owned by the kernel rather than a plugin.

``service_timekeeper`` used to be the third thing on the always-trusted list, and
its citation was capability #2: it owned a scheduler thread and touched the bus
directly. ``runtime/service_ticker.py`` retired the thread half (one kernel clock
ticks every service that asks) and the bus half (a tick *returns* the events it
wants fired). What nobody had done was walk through the exit, because the plugin
still owned the state as well as the loop.

This module is where that state moved. It holds the job table, normalizes and
validates definitions, and computes next-fire times with ``croniter``. That
placement is not incidental:

- **Cron arithmetic is infrastructure, not plugin logic.** A sandboxed body may
  import ``datetime`` but not ``croniter``, and widening the import gate to admit
  a third-party package so one plugin can do its own scheduling math would trade
  a real boundary for a cosmetic conversion.
- **The store outlives any one caller.** The orchestrator seeds a task's
  ``default_jobs`` at registration, ``/schedule`` edits them, the ticker advances
  them. A plugin holding that state would have to hand out a live handle, which
  is capability #1 all over again.

What the plugin keeps is the part that is genuinely its own: deciding which jobs
are due right now and what payload each fired event carries. See
``plugins/services/service_timekeeper.py``.

**Why job CRUD is not an administration verb.** Creating a job is dangerous
exactly in proportion to what its channel triggers — which is the argument
``service_ticker.channel_danger_tier`` already makes, and it is checked at the
*emit*, where the effect actually lands. Checking it a second time at declaration
would gate the scheduler's own bookkeeping behind an approval on every tick.
"""

from __future__ import annotations

import json
import logging
import threading
from copy import deepcopy
from datetime import datetime

from croniter import croniter

logger = logging.getLogger("Scheduling")


def now_local() -> datetime:
    """The current local time, timezone-aware."""
    return datetime.now().astimezone()


def _local_tz():
    """The local timezone."""
    return now_local().tzinfo


def cron_to_text(expr: str) -> str:
    """Human-readable description of a cron expression. Raises ``ValueError``."""
    from cron_descriptor import ExpressionDescriptor

    try:
        return ExpressionDescriptor(expr).get_description()
    except Exception as e:  # noqa: BLE001 — any parse failure is the same answer
        raise ValueError(f"Invalid cron expression: {e}")


def parse_datetime(value: str, job_name: str) -> datetime:
    """Parse a ``run_at`` value, defaulting a naive value to local time."""
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError) as e:
        raise ValueError(f"Job '{job_name}' has invalid run_at datetime: {e}")
    return dt.replace(tzinfo=_local_tz()) if dt.tzinfo is None else dt.astimezone()


def normalize_job(name: str, job_def: dict) -> dict:
    """Validate and canonicalize one job definition. Raises ``ValueError``."""
    job = {
        "enabled": bool(job_def.get("enabled", True)),
        "channel": (job_def.get("channel") or "").strip(),
        "cron": job_def.get("cron"),
        "run_at": job_def.get("run_at"),
        "one_time": bool(job_def.get("one_time", False)),
        "payload": deepcopy(job_def.get("payload", {})),
    }

    if not job["channel"]:
        raise ValueError(f"Job '{name}' is missing required field 'channel'.")
    if not isinstance(job["payload"], dict):
        raise ValueError(f"Job '{name}' payload must be a JSON object.")
    try:
        json.dumps(job["payload"])
    except TypeError as e:
        raise ValueError(f"Job '{name}' payload must be JSON-serializable: {e}")

    if job["one_time"]:
        if not job["run_at"]:
            raise ValueError(f"One-time job '{name}' requires 'run_at'.")
        if job["cron"]:
            raise ValueError(f"One-time job '{name}' must not define 'cron'.")
        job["run_at"] = parse_datetime(job["run_at"], name).isoformat()
        job["cron"] = None
    else:
        if not job["cron"]:
            raise ValueError(f"Repeating job '{name}' requires 'cron'.")
        if job["run_at"]:
            raise ValueError(f"Repeating job '{name}' must not define 'run_at'.")
        try:
            croniter(job["cron"], now_local())
        except Exception as e:  # noqa: BLE001
            raise ValueError(f"Job '{name}' has invalid cron expression: {e}")
        job["run_at"] = None

    return job


def compute_next_fire(job: dict, from_time: datetime) -> datetime | None:
    """When this job next fires after ``from_time``, or ``None`` if never again."""
    if not job.get("enabled", True):
        return None
    if job["one_time"]:
        run_at = parse_datetime(job["run_at"], "one_time job")
        return run_at if run_at >= from_time else None
    return croniter(job["cron"], from_time).get_next(datetime)


class JobStore:
    """The scheduled-job table: normalized definitions plus their next-fire times.

    Persists to plugin config under ``scheduled_jobs`` — the same place the
    timekeeper always kept them, so this move changes where the *code* lives
    without migrating anyone's data.
    """

    def __init__(self, config: dict):
        """Bind to the live config dict and load whatever it already holds."""
        self._config = config if config is not None else {}
        self._lock = threading.RLock()
        self._jobs: dict[str, dict] = {}
        self._next_fire_at: dict[str, datetime | None] = {}
        self.reload()

    # ── loading and persistence ──────────────────────────────────────────

    def reload(self, purge_expired: bool = False) -> None:
        """Rebuild the table from config, optionally dropping lapsed one-times."""
        raw = self._config.get("scheduled_jobs", {})
        if isinstance(raw, str):
            raw = raw.strip()
            raw = json.loads(raw) if raw else {}
        if raw is None:
            raw = {}
        if not isinstance(raw, dict):
            raise ValueError("scheduled_jobs must be a JSON object keyed by job name.")

        jobs: dict[str, dict] = {}
        next_fire: dict[str, datetime | None] = {}
        now = now_local()
        purged = []
        for name, job_def in raw.items():
            if not isinstance(job_def, dict):
                raise ValueError(f"Job '{name}' must be an object.")
            normalized = normalize_job(name, job_def)
            if purge_expired and normalized["one_time"] \
                    and parse_datetime(normalized["run_at"], name) < now:
                purged.append(name)
                continue
            jobs[name] = normalized
            next_fire[name] = compute_next_fire(normalized, from_time=now)

        with self._lock:
            self._jobs = jobs
            self._next_fire_at = next_fire
            if purged:
                logger.info(f"Purged expired one-time job(s): {', '.join(sorted(purged))}")
                self._persist()

    def _persist(self) -> None:
        """Write the table back to plugin config. Caller holds the lock."""
        from config import config_manager

        plugin_values = config_manager.load_plugin_config()
        plugin_values["scheduled_jobs"] = deepcopy(self._jobs)
        config_manager.save_plugin_config(plugin_values)
        self._config["scheduled_jobs"] = deepcopy(self._jobs)

    # ── reads ────────────────────────────────────────────────────────────

    def list_jobs(self) -> dict[str, dict]:
        """Every job, by name."""
        with self._lock:
            return {name: deepcopy(job) for name, job in self._jobs.items()}

    def get_job(self, name: str) -> dict | None:
        """One job by name, or ``None``."""
        with self._lock:
            job = self._jobs.get(name)
            return deepcopy(job) if job is not None else None

    def channels(self) -> list[str]:
        """Distinct channels the current jobs fire on.

        This is what the timekeeper declares to the ticker. Job channels are
        configured rather than hard-coded, so the declaration is necessarily
        dynamic — and it stays an honest authority check because the ticker
        grades every emit by what the channel triggers regardless."""
        with self._lock:
            return sorted({job["channel"] for job in self._jobs.values() if job.get("channel")})

    def get_next_fire_at(self, name: str) -> datetime | None:
        """Next fire time for a job, or ``None`` if disabled/unknown/exhausted."""
        with self._lock:
            job = self._jobs.get(name)
            if job is None or not job.get("enabled", True):
                return None
            cached = self._next_fire_at.get(name)
            return cached if cached is not None else compute_next_fire(job, from_time=now_local())

    def describe_job(self, name: str) -> str:
        """A human-readable schedule description. Raises ``ValueError``."""
        with self._lock:
            job = self._jobs.get(name)
            if job is None:
                raise ValueError(f"Unknown job: '{name}'.")
            return f"One-time at {job['run_at']}" if job["one_time"] else cron_to_text(job["cron"])

    def snapshot(self) -> list[dict]:
        """Every job as plain JSON-able data, next-fire times as ISO strings.

        The shape a sandboxed body sees. Datetimes do not cross the protocol, so
        they are stringified here rather than in the plugin."""
        with self._lock:
            out = []
            for name, job in sorted(self._jobs.items()):
                fire = self._next_fire_at.get(name)
                if fire is None and job.get("enabled", True):
                    fire = compute_next_fire(job, from_time=now_local())
                    self._next_fire_at[name] = fire
                out.append({**deepcopy(job), "name": name,
                            "next_fire_at": fire.isoformat() if fire else None})
            return out

    # ── mutations ────────────────────────────────────────────────────────

    def create_job(self, name: str, job_def: dict) -> dict:
        """Add a job. Raises ``ValueError`` if the name is taken or invalid."""
        with self._lock:
            if name in self._jobs:
                raise ValueError(f"Job '{name}' already exists.")
            normalized = normalize_job(name, job_def)
            self._jobs[name] = normalized
            self._next_fire_at[name] = compute_next_fire(normalized, from_time=now_local())
            self._persist()
            return deepcopy(normalized)

    def update_job(self, name: str, patch: dict) -> dict:
        """Merge ``patch`` into a job and re-validate the result."""
        with self._lock:
            current = self._jobs.get(name)
            if current is None:
                raise ValueError(f"Unknown job: '{name}'.")
            merged = deepcopy(current)
            merged.update(deepcopy(patch or {}))
            normalized = normalize_job(name, merged)
            self._jobs[name] = normalized
            self._next_fire_at[name] = compute_next_fire(normalized, from_time=now_local())
            self._persist()
            return deepcopy(normalized)

    def remove_job(self, name: str) -> bool:
        """Delete a job. ``False`` if it was not there.

        A removed default job reappears when its task next registers (boot,
        reinstall, hot-reload) — disabling is the durable way to silence one.
        """
        with self._lock:
            removed = self._jobs.pop(name, None)
            self._next_fire_at.pop(name, None)
            if removed is None:
                return False
            self._persist()
            return True

    def enable_job(self, name: str, enabled: bool = True) -> dict:
        """Enable or disable a job."""
        return self.update_job(name, {"enabled": bool(enabled)})

    def advance(self, names: list[str], fired_at: dict[str, str] | None = None) -> list[str]:
        """Move the named jobs past the fire they just had.

        Repeating jobs get a fresh next-fire computed from the time they were
        *scheduled for*, not from now — otherwise a slow tick would drift the
        schedule forward a little on every cycle. One-time jobs are removed.
        Returns the names that were removed.
        """
        fired_at = fired_at or {}
        removed = []
        with self._lock:
            dirty = False
            for name in names:
                job = self._jobs.get(name)
                if job is None:
                    continue
                if job["one_time"]:
                    self._jobs.pop(name, None)
                    self._next_fire_at.pop(name, None)
                    removed.append(name)
                    dirty = True
                    continue
                try:
                    base = parse_datetime(fired_at[name], name) if name in fired_at else now_local()
                except ValueError:
                    base = now_local()
                self._next_fire_at[name] = compute_next_fire(job, from_time=base)
            if dirty:
                self._persist()
        return removed

    # ── undo support ─────────────────────────────────────────────────────

    def capture(self, names: list[str] | None = None) -> dict:
        """Snapshot enough state to reverse a mutation.

        Scheduling changes are journalled as write-tier effects, so they need a
        real undo rather than a promise of one. ``None`` captures the whole
        table (for a create, whose undo must know the name did not exist)."""
        with self._lock:
            keys = list(self._jobs) if names is None else list(names)
            return {
                "jobs": {k: deepcopy(self._jobs[k]) for k in keys if k in self._jobs},
                "next_fire_at": {k: self._next_fire_at.get(k) for k in keys},
                "present": [k for k in keys if k in self._jobs],
                "keys": keys,
            }

    def restore(self, state: dict) -> None:
        """Reverse a mutation captured by :meth:`capture`."""
        with self._lock:
            for key in state.get("keys", []):
                if key in state.get("jobs", {}):
                    self._jobs[key] = deepcopy(state["jobs"][key])
                    self._next_fire_at[key] = state.get("next_fire_at", {}).get(key)
                else:
                    self._jobs.pop(key, None)
                    self._next_fire_at.pop(key, None)
            self._persist()


# ── the process-wide store ───────────────────────────────────────────────
#
# One store per process, bound to the live config dict. A module global rather
# than something threaded through every call site because the orchestrator, the
# ticker, the inventory provider and the administration surface all need the
# same table, and they are reached from four different directions.

_STORE: JobStore | None = None


def get_store(config: dict | None = None) -> JobStore:
    """The process-wide job store, built on first use."""
    global _STORE
    if _STORE is None:
        _STORE = JobStore(config if config is not None else {})
    return _STORE


def reset_store(config: dict | None = None) -> JobStore:
    """Rebuild the store against ``config``. For boot and for tests."""
    global _STORE
    _STORE = JobStore(config if config is not None else {})
    return _STORE

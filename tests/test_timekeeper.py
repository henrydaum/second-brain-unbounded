"""The scheduler, after its trusted exception was retired.

``service_timekeeper`` used to cite capability #2 — it owned a thread and it
called ``bus.emit``. Both halves moved to the kernel (``runtime/service_ticker.py``
drives the tick; ``runtime/scheduling.py`` owns the job table), leaving a plugin
that only decides which jobs are due. These tests cover both sides of that split:
the store's arithmetic, and the real service body driven through its kernel entry
point in both execution modes.
"""

from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]

from plugins.services.service_timekeeper import TimekeeperService
from runtime.scheduling import JobStore


def _job(**kwargs):
    data = {"enabled": True, "channel": "test.event", "payload": {},
            "one_time": False, "cron": "* * * * *"}
    data.update(kwargs)
    return data


@pytest.fixture
def saved(monkeypatch):
    """Capture plugin-config writes instead of touching the real file."""
    store: dict = {"other": "kept"}
    monkeypatch.setattr("config.config_manager.load_plugin_config", lambda: dict(store))
    monkeypatch.setattr("config.config_manager.save_plugin_config", store.update)
    return store


# ── the store ────────────────────────────────────────────────────────────

def test_reload_purges_expired_one_time_jobs(saved):
    now = datetime.now().astimezone()
    config = {"scheduled_jobs": {
        "past": _job(one_time=True, cron=None, run_at=(now - timedelta(days=1)).isoformat()),
        "future": _job(one_time=True, cron=None, run_at=(now + timedelta(days=1)).isoformat()),
        "cron": _job(),
    }}
    store = JobStore(config)
    store.reload(purge_expired=True)

    assert sorted(store.list_jobs()) == ["cron", "future"]
    assert sorted(config["scheduled_jobs"]) == ["cron", "future"]
    assert sorted(saved["scheduled_jobs"]) == ["cron", "future"]
    assert saved["other"] == "kept", "an unrelated plugin setting must survive"


def test_construction_does_not_persist_expired_jobs(monkeypatch):
    """Loading is not a mutation. Only an explicit purge writes."""
    now = datetime.now().astimezone()
    config = {"scheduled_jobs": {
        "past": _job(one_time=True, cron=None, run_at=(now - timedelta(days=1)).isoformat()),
    }}
    monkeypatch.setattr(
        "config.config_manager.save_plugin_config",
        lambda _values: (_ for _ in ()).throw(AssertionError("should not persist")))

    assert sorted(JobStore(config).list_jobs()) == ["past"]


def test_remove_and_recreate(saved):
    store = JobStore({"scheduled_jobs": {"cron": _job(channel="t")}})

    assert store.remove_job("cron") is True
    assert store.get_job("cron") is None
    assert saved["scheduled_jobs"] == {}
    assert store.remove_job("cron") is False  # already gone

    store.create_job("cron", {"channel": "t", "cron": "* * * * *"})
    assert store.get_job("cron") is not None


def test_channels_are_what_the_jobs_name(saved):
    """The timekeeper's declared channels are dynamic, so this is the authority
    check the ticker applies — it must reflect the live table."""
    store = JobStore({"scheduled_jobs": {"a": _job(channel="x"), "b": _job(channel="y")}})
    assert store.channels() == ["x", "y"]
    store.remove_job("b")
    assert store.channels() == ["x"]


def test_advance_computes_from_the_scheduled_time_not_from_now(saved):
    """Otherwise a slow tick drifts a repeating schedule forward every cycle."""
    store = JobStore({"scheduled_jobs": {"j": _job(cron="*/5 * * * *")}})
    due = store.snapshot()[0]["next_fire_at"]

    store.advance(["j"], {"j": due})
    after = store.get_next_fire_at("j")

    assert after.isoformat() != due
    assert (after - datetime.fromisoformat(due)) == timedelta(minutes=5)


def test_advance_removes_a_fired_one_time_job(saved):
    now = datetime.now().astimezone()
    store = JobStore({"scheduled_jobs": {
        "once": _job(one_time=True, cron=None, run_at=(now + timedelta(minutes=1)).isoformat()),
    }})
    assert store.advance(["once"]) == ["once"]
    assert store.get_job("once") is None


def test_capture_and_restore_reverses_a_mutation(saved):
    """ScheduleOp is graded *write*, which is a promise the turn can roll back."""
    store = JobStore({"scheduled_jobs": {"j": _job(channel="x")}})

    state = store.capture(["j"])
    store.remove_job("j")
    assert store.get_job("j") is None

    store.restore(state)
    assert store.get_job("j")["channel"] == "x"


# ── the real service body, both execution modes ──────────────────────────

def _tick_context(config, trusted: bool):
    """A context for driving the real tick, with only the surfaces it needs."""
    return SimpleNamespace(
        db=None, services={}, runtime=None, session_key=None, user_id=1,
        root_dir=".", approve_command=None, approval_denial_reason="",
        request_user_input=None, tool_registry=None, administer=None,
        config={**config, "sandbox_trust_all": trusted})


def _place(service, tmp_path, trusted: bool):
    """Point the service at trusted or untrusted bytes.

    Setting ``sandbox_trust_all`` would not do: the built-in path is trusted by
    provenance, so both halves of a flag-toggled parametrization would run
    in-process and prove nothing. Copying the same source somewhere untrusted is
    what actually forces the subprocess."""
    source = ROOT / "plugins" / "services" / "service_timekeeper.py"
    if trusted:
        service._source_path = str(source)
        return
    copy = tmp_path / "service_timekeeper.py"
    copy.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    service._source_path = str(copy)


@pytest.mark.parametrize("trusted", [True, False])
def test_the_real_timekeeper_ticks_through_its_entry_point(saved, tmp_path, trusted):
    """The migration's central property: identical behaviour in both execution
    modes. A due job produces one event and its clock advances; nothing is
    emitted by the plugin itself, in either mode."""
    from plugins.helpers.plugin_paths import is_trusted
    from runtime import scheduling

    now = datetime.now().astimezone()
    config = {"scheduled_jobs": {
        "due": _job(one_time=True, cron=None, run_at=(now + timedelta(hours=1)).isoformat()),
        "later": _job(one_time=True, cron=None, run_at=(now + timedelta(days=1)).isoformat()),
    }}
    store = scheduling.reset_store(config)
    # Wind one job's clock back rather than seeding it already-lapsed: a
    # one-time job whose moment passed while nothing was ticking is purged at
    # load, never fired late (see the test below). "Due right now" is the state
    # a running scheduler actually reaches, and it is what the tick must catch.
    store._next_fire_at["due"] = now - timedelta(seconds=1)

    service = TimekeeperService(config)
    _place(service, tmp_path, trusted)
    assert is_trusted(service._source_path) is trusted, "the mode under test is real"
    try:
        events = service.perform("tick", {}, _tick_context(config, False))
    finally:
        service.release_sandbox()

    assert [e["channel"] for e in events] == ["test.event"]
    assert events[0]["payload"]["_timekeeper"]["job_name"] == "due"
    assert events[0]["payload"]["_timekeeper"]["source"] == "timekeeper"
    # The fired one-time job is gone; the future one is untouched.
    assert sorted(store.list_jobs()) == ["later"]


def test_a_tick_with_nothing_due_returns_no_events(saved):
    from runtime import scheduling

    now = datetime.now().astimezone()
    config = {"scheduled_jobs": {
        "later": _job(one_time=True, cron=None, run_at=(now + timedelta(days=1)).isoformat()),
    }}
    scheduling.reset_store(config)

    service = TimekeeperService(config)
    service._source_path = "plugins/services/service_timekeeper.py"
    assert service.perform("tick", {}, _tick_context(config, True)) == []


def test_the_ticker_fires_a_due_job_end_to_end(saved):
    """The whole retired capability, in one pass: the kernel's clock drives the
    body, the body returns an event, the ticker puts it on the bus.

    This also pins an ordering bug that a unit test could not see. The
    timekeeper's channels are resolved from live state, and its tick *removes*
    the one-time job it fired — so resolving the declaration after the body ran
    found an empty table and refused the very emit the tick existed for. The
    declaration has to be read against the world the body started in.
    """
    import time

    from events.event_bus import bus
    from runtime import scheduling
    from runtime.service_ticker import ServiceTicker

    now = datetime.now().astimezone()
    config = {"scheduled_jobs": {"j": _job(one_time=True, cron=None, channel="tick.demo",
                                           payload={"hi": 1},
                                           run_at=(now + timedelta(hours=1)).isoformat())}}
    store = scheduling.reset_store(config)
    store._next_fire_at["j"] = now - timedelta(seconds=1)

    got = []
    bus.subscribe("tick.demo", got.append)

    service = TimekeeperService(config)
    service._source_path = str(ROOT / "plugins" / "services" / "service_timekeeper.py")
    service.loaded = True

    ticker = ServiceTicker({"timekeeper": service}, lambda _n: _tick_context(config, False),
                           poll_interval_s=0.1, tasks={})
    ticker.start()
    try:
        deadline = time.monotonic() + 5.0
        while not got and time.monotonic() < deadline:
            time.sleep(0.05)
    finally:
        ticker.stop()

    assert len(got) == 1, "the due job should have fired exactly once"
    assert got[0]["hi"] == 1
    assert got[0]["_timekeeper"]["job_name"] == "j"
    assert store.list_jobs() == {}, "a fired one-time job is removed"


def test_a_lapsed_one_time_job_is_dropped_rather_than_fired_late(saved):
    """Missing the moment is not the same as being due. A one-time job whose
    time passed while the app was down has no next fire, so the tick skips it and
    the boot purge removes it — firing a week-old reminder on restart would be
    worse than dropping it."""
    from runtime import scheduling

    now = datetime.now().astimezone()
    config = {"scheduled_jobs": {
        "lapsed": _job(one_time=True, cron=None, run_at=(now - timedelta(days=1)).isoformat()),
    }}
    store = scheduling.reset_store(config)

    service = TimekeeperService(config)
    service._source_path = "plugins/services/service_timekeeper.py"
    assert service.perform("tick", {}, _tick_context(config, True)) == []

    store.reload(purge_expired=True)
    assert store.list_jobs() == {}


def test_a_disabled_job_never_fires(saved):
    from runtime import scheduling

    now = datetime.now().astimezone()
    config = {"scheduled_jobs": {
        "off": _job(enabled=False, one_time=True, cron=None,
                    run_at=(now - timedelta(minutes=1)).isoformat()),
    }}
    scheduling.reset_store(config)

    service = TimekeeperService(config)
    service._source_path = "plugins/services/service_timekeeper.py"
    assert service.perform("tick", {}, _tick_context(config, True)) == []

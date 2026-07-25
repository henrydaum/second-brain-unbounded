"""Default Timekeeper job lifecycle: BaseTask.default_jobs.

Covers the kernel half of "installing a scheduling task should schedule
it": the orchestrator seeds declared default jobs at registration
(existing jobs — including disabled ones — are left alone) and removes
them at unregistration, so a task's default jobs live exactly as long as
the task does and a reinstall picks up updated declarations.
"""

from types import SimpleNamespace

import pytest

from pipeline.orchestrator import Orchestrator
from plugins.BaseTask import BaseTask
from runtime.runtime_approvals import _sane_enum
from runtime.scheduling import reset_store


@pytest.fixture(autouse=True)
def _isolated_store(monkeypatch):
    """Keep the process-wide job store out of the user's real config file.

    The store, not the timekeeper service, is what the orchestrator seeds into
    now — the service holds no job state at all since its trusted exception was
    retired."""
    saved: dict = {}
    monkeypatch.setattr("config.config_manager.load_plugin_config", lambda: dict(saved))
    monkeypatch.setattr("config.config_manager.save_plugin_config", saved.update)
    yield reset_store({})
    reset_store({})


class _SeederTask(BaseTask):
    name = "seeder"
    trigger = "event"
    trigger_channels = ["seed.chan"]
    default_jobs = {"seed_job": {"channel": "seed.chan", "cron": "*/15 * * * *", "payload": {}}}


def _orchestrator(with_timekeeper=True):
    db = SimpleNamespace(
        ensure_output_table=lambda *a, **k: None,
        register_task=lambda **k: None,
    )
    services = {"timekeeper": object()} if with_timekeeper else {}
    return Orchestrator(db, {"max_workers": 1}, services)


def test_register_task_seeds_declared_default_jobs(_isolated_store):
    _orchestrator().register_task(_SeederTask())
    job = _isolated_store.get_job("seed_job")
    assert job["cron"] == "*/15 * * * *"
    assert job["channel"] == "seed.chan"


def test_seeding_skips_existing_jobs(_isolated_store):
    _isolated_store.create_job("seed_job", {"channel": "other.chan", "cron": "0 0 * * *"})
    _orchestrator().register_task(_SeederTask())
    assert _isolated_store.get_job("seed_job")["channel"] == "other.chan"


def test_seeding_is_skipped_without_a_scheduler(_isolated_store):
    """No timekeeper installed means no clock, so a seeded job would be a
    phantom schedule sitting in config that nothing will ever fire."""
    _orchestrator(with_timekeeper=False).register_task(_SeederTask())
    assert _isolated_store.get_job("seed_job") is None


def test_unregister_removes_default_jobs(_isolated_store):
    orch = _orchestrator()
    orch.register_task(_SeederTask())
    assert _isolated_store.get_job("seed_job") is not None

    orch.unregister_task("seeder")

    assert _isolated_store.get_job("seed_job") is None


def test_reinstall_reseeds_updated_declaration(_isolated_store):
    # Uninstall + reinstall with a changed cron: the old job is removed at
    # unregistration, so the new registration seeds the new schedule.
    orch = _orchestrator()
    orch.register_task(_SeederTask())
    orch.unregister_task("seeder")

    class _Updated(_SeederTask):
        default_jobs = {"seed_job": {"channel": "seed.chan", "cron": "* * * * *", "payload": {}}}

    orch.register_task(_Updated())
    assert _isolated_store.get_job("seed_job")["cron"] == "* * * * *"


def test_task_without_default_jobs_needs_no_timekeeper():
    class _Plain(BaseTask):
        name = "plain"
        trigger = "event"
        trigger_channels = ["plain.chan"]

    db = SimpleNamespace(ensure_output_table=lambda *a, **k: None, register_task=lambda **k: None)
    Orchestrator(db, {"max_workers": 1}, {}).register_task(_Plain())  # must not raise


def test_sane_enum_drops_unanswerable_choices():
    # A request whose every choice renders empty would wedge the session —
    # the kernel treats it as free-form input instead.
    assert _sane_enum(["", "  ", ""]) is None
    assert _sane_enum(["a", "", "b"]) == ["a", "b"]
    assert _sane_enum(None) is None
    assert _sane_enum([]) is None
    assert _sane_enum([True, False]) == [True, False]

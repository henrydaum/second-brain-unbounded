"""Tasks on the effects contract — the third family across the boundary.

Tasks are the family with the strictest output contract: the orchestrator writes
``TaskResult.data`` straight into the task's declared tables and expects exactly
one result per input path. So the interesting cases are not the happy path but
the shapes a sandboxed task can return that would corrupt that contract — a
short list, a malformed row, a bare dict where a list was expected.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from plugins.BaseTask import BaseTask, TaskResult, _to_task_results


class _EffectsTask(BaseTask):
    """Reads each path and reports its length as an output row."""

    contract = "effects"
    name = "count_chars"
    writes = ["counts"]
    declared_requests = ["read_files"]

    def run(self, params):
        from effects.vocabulary import ReadFiles, Respond
        got = yield ReadFiles(paths=params["paths"])
        rows = []
        for entry in (got.value or {}).get("files", []):
            rows.append({"success": True,
                         "data": [{"path": entry.get("path"),
                                   "n": len(entry.get("text") or "")}]})
        return Respond(data=rows)


class _EffectsEventTask(BaseTask):
    """Event-triggered variant."""

    contract = "effects"
    name = "on_event"
    trigger = "event"
    writes = ["events"]
    declared_requests = []

    def run_event(self, params):
        from effects.vocabulary import Respond
        return Respond(data={"success": True,
                             "data": [{"run_id": params["run_id"],
                                       "note": params["payload"].get("note", "")}]})


class _LegacyTask(BaseTask):
    """The historical shape, which must keep working unchanged."""

    name = "legacy_task"
    writes = ["legacy"]

    def run(self, paths, context):
        return [TaskResult(data=[{"path": p}]) for p in paths]

    def run_event(self, run_id, payload, context):
        return TaskResult(data=[{"run_id": run_id}])


def _context(tmp_path, trust_all=True):
    """A minimal context confined to tmp_path. Tasks get no session_key."""
    return SimpleNamespace(
        db=None, services={}, runtime=None, session_key=None, user_id=None,
        root_dir=str(tmp_path), approve_command=None, approval_denial_reason="",
        config={"sandbox_read_roots": [str(tmp_path)],
                "sandbox_write_roots": [str(tmp_path)],
                "sandbox_trust_all": trust_all, "tool_timeout": 25},
    )


def _task(cls=_EffectsTask):
    """Instantiate with a source path so provenance can be resolved."""
    task = cls()
    task._source_path = __file__
    return task


def test_effects_task_returns_rows_per_path(tmp_path):
    """The body's data becomes TaskResults; the kernel builds them, so a
    sandboxed task never holds one."""
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("abc", encoding="utf-8")
    b.write_text("de", encoding="utf-8")

    results = _task().perform([str(a), str(b)], _context(tmp_path))

    assert len(results) == 2
    assert all(isinstance(r, TaskResult) for r in results)
    assert sorted(r.data[0]["n"] for r in results) == [2, 3]


def test_event_task_returns_a_single_result(tmp_path):
    """The event entry point is driven through the same boundary, via a second
    method name rather than a side channel."""
    result = _task(_EffectsEventTask).perform_event(
        "run-1", {"note": "hi"}, _context(tmp_path))

    assert isinstance(result, TaskResult)
    assert result.success
    assert result.data == [{"run_id": "run-1", "note": "hi"}]


def test_legacy_task_is_untouched(tmp_path):
    """The default contract keeps the historical signature."""
    task = _task(_LegacyTask)

    results = task.perform(["p1", "p2"], _context(tmp_path))
    assert [r.data[0]["path"] for r in results] == ["p1", "p2"]
    assert task.perform_event("r1", {}, _context(tmp_path)).data == [{"run_id": "r1"}]


def test_a_failing_task_fails_every_path_in_the_batch(tmp_path):
    """The orchestrator marks each path from its result, so a batch-level
    failure must produce one failure per path rather than an empty list —
    otherwise paths would silently look unprocessed."""

    class _Undeclared(BaseTask):
        contract = "effects"
        name = "undeclared_task"
        declared_requests = []

        def run(self, params):
            from effects.vocabulary import ReadFiles, Respond
            yield ReadFiles(paths=params["paths"])
            return Respond(data=[])

    results = _task(_Undeclared).perform(["p1", "p2", "p3"], _context(tmp_path))

    assert len(results) == 3
    assert all(not r.success for r in results)
    assert all("undeclared request" in r.error for r in results)


def test_a_short_result_list_is_padded_not_truncated(tmp_path):
    """One result per input path is the orchestrator's contract; a task that
    under-reports must not leave paths unaccounted for."""

    class _Lazy(BaseTask):
        contract = "effects"
        name = "lazy"
        declared_requests = []

        def run(self, params):
            from effects.vocabulary import Respond
            return Respond(data=[{"success": True, "data": []}])
            yield  # noqa

    results = _task(_Lazy).perform(["p1", "p2", "p3"], _context(tmp_path))

    assert len(results) == 3
    assert results[0].success
    assert not results[1].success and not results[2].success


def test_task_result_payload_is_validated_not_believed():
    """Unknown keys are dropped and malformed entries skipped — the payload
    crosses a boundary from code the kernel does not trust, and it lands in a
    database write."""
    results = _to_task_results([
        {"success": True, "data": [{"x": 1}], "bogus_key": "ignored"},
        "not a dict",
        {"success": False, "error": "real failure"},
    ])

    assert len(results) == 2
    assert results[0].data == [{"x": 1}]
    assert not hasattr(results[0], "bogus_key")
    assert results[1].error == "real failure"


def test_a_bare_dict_is_accepted_as_one_result():
    """The event path returns a single result; accepting either shape keeps the
    two entry points from needing different return conventions."""
    results = _to_task_results({"success": True, "data": [{"a": 1}]})

    assert len(results) == 1
    assert results[0].data == [{"a": 1}]


def test_danger_tier_is_derived_for_tasks():
    """Tier comes from declarations, exactly as for tools and commands."""
    assert _task().danger_tier == "read"

    class _Writer(BaseTask):
        contract = "effects"
        name = "tw"
        declared_requests = ["write_db"]

    assert _Writer().danger_tier == "write"


@pytest.mark.parametrize("trust_all", [True, False], ids=["trusted", "untrusted"])
def test_task_behaves_identically_in_both_modes(tmp_path, trust_all):
    """The all-trusted equivalence invariant, at the task family."""
    target = tmp_path / "a.txt"
    target.write_text("abc", encoding="utf-8")

    source = tmp_path / "task_count.py"
    source.write_text(
        "from plugins.BaseTask import BaseTask\n"
        "from effects.vocabulary import ReadFiles, Respond\n\n\n"
        "class CountTask(BaseTask):\n"
        '    contract = "effects"\n'
        '    name = "count_chars"\n'
        '    declared_requests = ["read_files"]\n\n'
        "    def run(self, params):\n"
        "        got = yield ReadFiles(paths=params['paths'])\n"
        "        rows = [{'success': True, 'data': [{'n': len(e.get('text') or '')}]}\n"
        "                for e in (got.value or {}).get('files', [])]\n"
        "        return Respond(data=rows)\n",
        encoding="utf-8")

    task = _EffectsTask()
    task._source_path = str(source)

    results = task.perform([str(target)], _context(tmp_path, trust_all=trust_all))

    assert len(results) == 1
    assert results[0].success, results[0].error
    assert results[0].data[0]["n"] == 3

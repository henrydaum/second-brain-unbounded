"""Tests for the primitives added in the foundation build: DeleteFile (write),
Embed / ExecSql / RunProcess (egress), and the ReadContext ambient views.

Same isolation as test_effects.py — the interpreter over real resources, no
sandbox subprocess.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from effects import (
    DeleteFile,
    EffectContext,
    Embed,
    ExecSql,
    Interpreter,
    ReadContext,
    RunProcess,
    TurnJournal,
    derive_tier,
    from_wire,
)
from effects.interpreter import default_egress_gate
from pipeline.database import Database

_ALLOW = lambda request: (True, "")  # noqa: E731 — permissive gate for egress tests


# ── wire round-trip + tiers ──────────────────────────────────────────────

@pytest.mark.parametrize("request_obj", [
    DeleteFile(path="/tmp/x.txt"),
    Embed(inputs=["a", "b"], model="m"),
    ExecSql(sql="DELETE FROM t WHERE id = 1"),
    RunProcess(argv=["echo", "hi"], cwd="/tmp", timeout=5.0),
])
def test_new_requests_wire_round_trip(request_obj):
    wire = request_obj.to_wire()
    assert wire["type"] == request_obj.type
    assert from_wire(wire) == request_obj


def test_new_request_tiers():
    assert derive_tier(["delete_file"]) == "write"
    assert derive_tier(["embed"]) == "egress"
    assert derive_tier(["exec_sql"]) == "egress"
    assert derive_tier(["run_process"]) == "egress"


# ── DeleteFile (journalled write) ────────────────────────────────────────

def test_delete_file_journalled_and_restored(tmp_path: Path):
    target = tmp_path / "doomed.txt"
    target.write_text("keepsafe", encoding="utf-8")
    journal = TurnJournal()
    interp = Interpreter(
        EffectContext(write_roots=[tmp_path], tool_name="del"),
        declared=["delete_file"], journal=journal)
    result = interp.fulfill(DeleteFile(path=str(target)))
    assert result.ok and result.value["existed"] is True
    assert not target.exists()

    journal.rollback()
    assert target.read_text() == "keepsafe"  # snapshot restored the bytes


def test_delete_missing_file_is_success_noop(tmp_path: Path):
    interp = Interpreter(
        EffectContext(write_roots=[tmp_path], tool_name="del"),
        declared=["delete_file"], journal=TurnJournal())
    result = interp.fulfill(DeleteFile(path=str(tmp_path / "ghost.txt")))
    assert result.ok and result.value["existed"] is False


def test_delete_outside_write_roots_denied(tmp_path: Path):
    victim = tmp_path / "outside.txt"
    victim.write_text("safe", encoding="utf-8")
    interp = Interpreter(
        EffectContext(write_roots=[tmp_path / "sandbox"], tool_name="del"),
        declared=["delete_file"], journal=TurnJournal())
    result = interp.fulfill(DeleteFile(path=str(victim)))
    assert not result.ok and "outside" in result.error
    assert victim.exists()  # untouched


# ── ExecSql (gated egress) ───────────────────────────────────────────────

def test_exec_sql_runs_mutation_when_allowed(tmp_path: Path):
    db = Database(str(tmp_path / "t.db"))
    interp = Interpreter(
        EffectContext(db=db, egress_gate=_ALLOW, tool_name="sql"),
        declared=["exec_sql"])
    interp.fulfill(ExecSql(sql="CREATE TABLE t (id INTEGER, done INTEGER)"))
    interp.fulfill(ExecSql(sql="INSERT INTO t (id, done) VALUES (1, 0)"))
    r = interp.fulfill(ExecSql(sql="UPDATE t SET done = 1 WHERE id = 1"))
    assert r.ok
    assert db.query("SELECT done FROM t WHERE id = 1")["rows"][0][0] == 1


def test_exec_sql_refuses_read_only(tmp_path: Path):
    db = Database(str(tmp_path / "t.db"))
    interp = Interpreter(
        EffectContext(db=db, egress_gate=_ALLOW, tool_name="sql"),
        declared=["exec_sql"])
    for sql in ("SELECT 1", "  select * from x", "PRAGMA table_info(t)",
                "-- a comment\nSELECT 2", "EXPLAIN SELECT 1"):
        r = interp.fulfill(ExecSql(sql=sql))
        assert not r.ok and "QueryDb" in r.error


def test_exec_sql_denied_by_default_gate(tmp_path: Path):
    db = Database(str(tmp_path / "t.db"))
    interp = Interpreter(
        EffectContext(db=db, tool_name="sql"),  # no gate → default denies egress
        declared=["exec_sql"])
    r = interp.fulfill(ExecSql(sql="DELETE FROM t"))
    assert not r.ok and r.denied


# ── Embed (kernel-served egress) ─────────────────────────────────────────

def test_embed_returns_vectors():
    fake = SimpleNamespace(model_name="tiny", encode=lambda xs: [[1.0, 2.0] for _ in xs])
    interp = Interpreter(EffectContext(embedder=fake, tool_name="emb"), declared=["embed"])
    r = interp.fulfill(Embed(inputs=["a", "b"]))
    assert r.ok and r.value["vectors"] == [[1.0, 2.0], [1.0, 2.0]]
    assert r.value["model"] == "tiny"


def test_embed_allowed_by_default_gate():
    ok, _ = default_egress_gate(Embed(inputs=["x"]))
    assert ok  # a kernel-served model, like Complete


def test_embed_no_embedder_errors():
    interp = Interpreter(EffectContext(tool_name="emb"), declared=["embed"])
    r = interp.fulfill(Embed(inputs=["a"]))
    assert not r.ok and "no embedder" in r.error


# ── RunProcess (gated subprocess egress) ─────────────────────────────────

def test_run_process_captures_output(tmp_path: Path):
    interp = Interpreter(
        EffectContext(read_roots=[tmp_path], egress_gate=_ALLOW, tool_name="proc"),
        declared=["run_process"])
    r = interp.fulfill(RunProcess(argv=[sys.executable, "-c", "print('hello proc')"]))
    assert r.ok and r.value["exit_code"] == 0
    assert "hello proc" in r.value["stdout"]


def test_run_process_cwd_confined(tmp_path: Path):
    interp = Interpreter(
        EffectContext(read_roots=[tmp_path / "allowed"], egress_gate=_ALLOW, tool_name="proc"),
        declared=["run_process"])
    r = interp.fulfill(RunProcess(argv=[sys.executable, "-c", "pass"], cwd=str(tmp_path)))
    assert not r.ok and "outside" in r.error


def test_run_process_empty_argv_rejected(tmp_path: Path):
    interp = Interpreter(
        EffectContext(read_roots=[tmp_path], egress_gate=_ALLOW, tool_name="proc"),
        declared=["run_process"])
    r = interp.fulfill(RunProcess(argv=[]))
    assert not r.ok and "argv" in r.error


def test_run_process_denied_by_default_gate(tmp_path: Path):
    interp = Interpreter(
        EffectContext(read_roots=[tmp_path], tool_name="proc"),  # default gate denies
        declared=["run_process"])
    r = interp.fulfill(RunProcess(argv=[sys.executable, "-c", "pass"]))
    assert not r.ok and r.denied


# ── ReadContext ambient views ────────────────────────────────────────────

def test_read_context_ambient_views():
    interp = Interpreter(
        EffectContext(conversation_id=42, user_id=7,
                      paths={"root": "/proj", "memory_root": "/proj/mem"}, tool_name="t"),
        declared=[])
    assert interp.fulfill(ReadContext(view="conversation_id")).value == 42
    assert interp.fulfill(ReadContext(view="user_id")).value == 7
    assert interp.fulfill(ReadContext(view="paths")).value == {"root": "/proj", "memory_root": "/proj/mem"}


def test_read_context_conversation_view_still_uses_provider():
    interp = Interpreter(
        EffectContext(context_provider=lambda view, k: f"text:{view}", tool_name="t"),
        declared=[])
    assert interp.fulfill(ReadContext(view="full")).value == "text:full"

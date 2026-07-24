"""Tests for the effect system: vocabulary wire round-trip, tier derivation,
undeclared-request rejection, journalled writes + turn rollback, and the egress
gate.

These exercise ``effects/`` in isolation — no live runtime, no sandbox. The
sandbox runner (Phase 3) reuses the same interpreter over a subprocess pipe.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from effects import (
    Complete,
    EffectContext,
    HttpRequest,
    Interpreter,
    ListDir,
    QueryDb,
    ReadContext,
    ReadFile,
    ReadFiles,
    Respond,
    Stat,
    TurnJournal,
    UndeclaredRequestError,
    WriteDb,
    WriteFile,
    derive_tier,
    from_wire,
)
from effects.interpreter import default_egress_gate
from pipeline.database import Database


# ── wire round-trip ──────────────────────────────────────────────────────

@pytest.mark.parametrize("request_obj", [
    ReadFile(path="/tmp/x.txt"),
    QueryDb(sql="SELECT 1", max_rows=5),
    ListDir(root="/tmp", recursive=False),
    ReadFiles(paths=["/tmp/a.py", "/tmp/b.py"]),
    Stat(path="/tmp/x.txt"),
    ReadContext(view="last_k", k=3),
    WriteFile(path="/tmp/y.txt", content="hi"),
    WriteDb(table="t", schema_sql="CREATE TABLE t (a INTEGER)", rows=[{"a": 1}]),
    Respond(summary="done", data={"n": 1}),
    HttpRequest(method="GET", url="https://example.com"),
    Complete(prompt="hello", schema={"type": "object"}),
])
def test_wire_round_trip(request_obj):
    """Every request serializes to tagged JSON and rebuilds identically."""
    wire = request_obj.to_wire()
    assert wire["type"] == request_obj.type
    assert from_wire(wire) == request_obj


def test_from_wire_unknown_type_raises():
    """An unknown discriminator is a hard reject."""
    with pytest.raises(KeyError):
        from_wire({"type": "not_a_request", "path": "x"})


def test_from_wire_extra_field_raises():
    """Extra fields off the pipe are rejected rather than silently dropped."""
    with pytest.raises(TypeError):
        from_wire({"type": "read_file", "path": "x", "sneaky": True})


# ── tier derivation ──────────────────────────────────────────────────────

def test_derive_tier_is_the_max():
    """Danger tier is the max across declared request types."""
    assert derive_tier([]) == "read"
    assert derive_tier(["read_file", "query_db"]) == "read"
    assert derive_tier(["read_file", "write_file"]) == "write"
    assert derive_tier(["read_file", "write_db", "complete"]) == "egress"
    assert derive_tier(["http_request"]) == "egress"


def test_derive_tier_rejects_unknown_tag():
    """A typo'd declaration surfaces at derivation, not as a silent gap."""
    with pytest.raises(ValueError):
        derive_tier(["reed_file"])


# ── undeclared-request rejection ─────────────────────────────────────────

def test_undeclared_request_is_hard_reject():
    """A request type the tool did not declare raises a contract violation."""
    interp = Interpreter(EffectContext(tool_name="reader"), declared=["read_file"])
    with pytest.raises(UndeclaredRequestError):
        interp.fulfill(WriteFile(path="/tmp/z", content="x"))


def test_implicit_requests_never_need_declaration():
    """Respond and ReadContext are always available and never counted."""
    interp = Interpreter(EffectContext(tool_name="t"), declared=[])
    # Neither raises UndeclaredRequestError.
    interp.fulfill(ReadContext(view="full"))
    interp.fulfill(Respond(summary="ok"))


# ── reads ────────────────────────────────────────────────────────────────

def test_read_file(tmp_path: Path):
    """ReadFile returns the file text."""
    f = tmp_path / "note.txt"
    f.write_text("the whole", encoding="utf-8")
    interp = Interpreter(
        EffectContext(read_roots=[tmp_path], tool_name="reader"),
        declared=["read_file"],
    )
    result = interp.fulfill(ReadFile(path=str(f)))
    assert result.ok and result.value == "the whole"


def test_read_file_outside_roots_denied(tmp_path: Path):
    """A read outside the allowed roots fails (handler error, not a crash)."""
    interp = Interpreter(
        EffectContext(read_roots=[tmp_path / "allowed"], tool_name="reader"),
        declared=["read_file"],
    )
    result = interp.fulfill(ReadFile(path=str(tmp_path / "secret.txt")))
    assert not result.ok and "allowed read roots" in result.error


def test_read_context_uses_provider():
    """ReadContext routes through the context provider."""
    seen = {}

    def provider(view, k):
        seen["view"], seen["k"] = view, k
        return "sliced context"

    interp = Interpreter(
        EffectContext(context_provider=provider, tool_name="t"),
        declared=[],
    )
    result = interp.fulfill(ReadContext(view="last_k", k=2))
    assert result.value == "sliced context"
    assert seen == {"view": "last_k", "k": 2}


# ── filesystem primitives (list_dir / read_files / stat) ─────────────────

def _tree(tmp_path: Path):
    """A small file tree for filesystem-primitive tests."""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "a.py").write_text("import os\nTODO fix this\n", encoding="utf-8")
    (tmp_path / "pkg" / "b.py").write_text("x = 1\n# TODO later\n", encoding="utf-8")
    (tmp_path / "pkg" / "c.txt").write_text("nothing here\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "junk.py").write_text("TODO ignored\n", encoding="utf-8")


def test_list_dir_enumerates_with_metadata_and_prunes_junk(tmp_path: Path):
    """ListDir returns rel path + size + mtime per file and prunes junk dirs."""
    _tree(tmp_path)
    interp = Interpreter(EffectContext(read_roots=[tmp_path], tool_name="lister"), declared=["list_dir"])
    result = interp.fulfill(ListDir(root=str(tmp_path)))
    entries = {e["path"]: e for e in result.value["entries"]}
    assert set(entries) == {"a.py", "pkg/b.py", "pkg/c.txt"}  # .git pruned
    assert entries["a.py"]["size"] > 0 and entries["a.py"]["mtime"] > 0


def test_list_dir_non_recursive_stays_top_level(tmp_path: Path):
    """recursive=False only lists the root's own files."""
    _tree(tmp_path)
    interp = Interpreter(EffectContext(read_roots=[tmp_path], tool_name="lister"), declared=["list_dir"])
    result = interp.fulfill(ListDir(root=str(tmp_path), recursive=False))
    assert {e["path"] for e in result.value["entries"]} == {"a.py"}


def test_list_dir_outside_roots_denied(tmp_path: Path):
    """A root outside the allowed read roots fails."""
    interp = Interpreter(
        EffectContext(read_roots=[tmp_path / "allowed"], tool_name="lister"), declared=["list_dir"])
    result = interp.fulfill(ListDir(root=str(tmp_path)))
    assert not result.ok and "read roots" in result.error


def test_read_files_batches_with_per_file_outcomes(tmp_path: Path):
    """ReadFiles returns text per readable file and errors per bad one,
    without failing the batch."""
    _tree(tmp_path)
    (tmp_path / "bin.dat").write_bytes(b"\x00\x01\x02")
    interp = Interpreter(EffectContext(read_roots=[tmp_path], tool_name="reader"), declared=["read_files"])
    result = interp.fulfill(ReadFiles(paths=[
        str(tmp_path / "a.py"),
        str(tmp_path / "bin.dat"),
        str(tmp_path / "missing.txt"),
        str(tmp_path.parent / "outside.txt"),
    ]))
    by_path = {Path(f["path"]).name: f for f in result.value["files"]}
    assert "TODO fix this" in by_path["a.py"]["text"]
    assert by_path["bin.dat"]["error"] == "binary file"
    assert "error" in by_path["missing.txt"]
    assert "read roots" in by_path["outside.txt"]["error"]


def test_stat_reports_metadata_and_absence(tmp_path: Path):
    """Stat returns kind/size/mtime for a real path, exists=False otherwise."""
    _tree(tmp_path)
    interp = Interpreter(EffectContext(read_roots=[tmp_path], tool_name="stat"), declared=["stat"])
    hit = interp.fulfill(Stat(path=str(tmp_path / "a.py")))
    assert hit.value["exists"] and not hit.value["is_dir"] and hit.value["size"] > 0
    miss = interp.fulfill(Stat(path=str(tmp_path / "nope.txt")))
    assert miss.value == {"path": str(tmp_path / "nope.txt"), "exists": False}


# ── writes + journal rollback ────────────────────────────────────────────

def test_write_file_journalled_and_rolled_back(tmp_path: Path):
    """A new file is created, then rollback deletes it (it didn't exist)."""
    target = tmp_path / "out" / "created.txt"
    journal = TurnJournal()
    interp = Interpreter(
        EffectContext(write_roots=[tmp_path], tool_name="writer"),
        declared=["write_file"],
        journal=journal,
    )
    interp.fulfill(WriteFile(path=str(target), content="fresh"))
    assert target.read_text() == "fresh"
    assert len(journal) == 1

    errors = journal.rollback()
    assert errors == []
    assert not target.exists()


def test_write_file_rollback_restores_prior_bytes(tmp_path: Path):
    """Overwriting an existing file, then rolling back, restores the original."""
    target = tmp_path / "existing.txt"
    target.write_text("original", encoding="utf-8")
    journal = TurnJournal()
    interp = Interpreter(
        EffectContext(write_roots=[tmp_path], tool_name="writer"),
        declared=["write_file"],
        journal=journal,
    )
    interp.fulfill(WriteFile(path=str(target), content="clobbered"))
    assert target.read_text() == "clobbered"
    journal.rollback()
    assert target.read_text() == "original"


def test_write_db_journalled_and_rolled_back(tmp_path: Path):
    """WriteDb inserts rows; rollback deletes exactly those rows."""
    db = Database(str(tmp_path / "t.db"))
    journal = TurnJournal()
    interp = Interpreter(
        EffectContext(db=db, tool_name="writer"),
        declared=["write_db"],
        journal=journal,
    )
    schema = "CREATE TABLE IF NOT EXISTS notes (body TEXT)"
    interp.fulfill(WriteDb(table="notes", schema_sql=schema, rows=[{"body": "a"}, {"body": "b"}]))
    assert db.query("SELECT COUNT(*) FROM notes")["rows"][0][0] == 2

    journal.rollback()
    assert db.query("SELECT COUNT(*) FROM notes")["rows"][0][0] == 0


def test_write_db_rollback_preserves_prior_rows(tmp_path: Path):
    """Rollback only removes rows this turn inserted, not pre-existing ones."""
    db = Database(str(tmp_path / "t.db"))
    db.ensure_output_table("notes", "CREATE TABLE notes (body TEXT)")
    db.write_outputs("notes", [{"body": "old"}])

    journal = TurnJournal()
    interp = Interpreter(
        EffectContext(db=db, tool_name="writer"),
        declared=["write_db"],
        journal=journal,
    )
    interp.fulfill(WriteDb(table="notes", schema_sql="CREATE TABLE IF NOT EXISTS notes (body TEXT)", rows=[{"body": "new"}]))
    journal.rollback()
    rows = db.query("SELECT body FROM notes")["rows"]
    assert rows == [("old",)]


# ── egress gate ──────────────────────────────────────────────────────────

def test_default_gate_allows_complete_denies_http():
    """The default policy allows LLM completion, denies raw HTTP."""
    ok, _ = default_egress_gate(Complete(prompt="hi"))
    assert ok
    denied, reason = default_egress_gate(HttpRequest(method="GET", url="https://x"))
    assert not denied and reason


def test_egress_denied_is_tool_visible_not_fatal():
    """A denied egress request comes back as denied, not an exception."""
    interp = Interpreter(
        EffectContext(egress_gate=lambda r: (False, "nope"), tool_name="t"),
        declared=["http_request"],
    )
    result = interp.fulfill(HttpRequest(method="GET", url="https://x"))
    assert not result.ok and result.denied and result.error == "nope"


def test_complete_served_by_llm():
    """Complete routes to the llm service's invoke and returns its content."""
    fake_llm = SimpleNamespace(
        invoke=lambda messages, **kw: SimpleNamespace(content="hi there", is_error=False),
    )
    interp = Interpreter(
        EffectContext(llm=fake_llm, tool_name="t"),
        declared=["complete"],
    )
    result = interp.fulfill(Complete(prompt="say hi"))
    assert result.ok and result.value == "hi there"


# ── ledger + journal wiring ──────────────────────────────────────────────

def test_fulfillment_recorded_to_ledger(tmp_path: Path):
    """Each fulfilment writes an origin='effect' ledger row."""
    db = Database(str(tmp_path / "t.db"))
    f = tmp_path / "x.txt"
    f.write_text("data")
    interp = Interpreter(
        EffectContext(db=db, read_roots=[tmp_path], tool_name="reader", conversation_id=7),
        declared=["read_file"],
    )
    interp.fulfill(ReadFile(path=str(f)))
    rows = db.get_ledger_rows(origin="effect")
    assert len(rows) == 1
    assert rows[0]["action_type"] == "read_file"
    assert rows[0]["conversation_id"] == 7


def test_write_records_effect_journal_row(tmp_path: Path):
    """A write-tier fulfilment leaves a durable effect_journal row."""
    db = Database(str(tmp_path / "t.db"))
    interp = Interpreter(
        EffectContext(db=db, write_roots=[tmp_path], tool_name="writer"),
        declared=["write_file"],
    )
    interp.fulfill(WriteFile(path=str(tmp_path / "j.txt"), content="x"))
    rows = db.query("SELECT request_type FROM effect_journal")["rows"]
    assert rows == [("write_file",)]

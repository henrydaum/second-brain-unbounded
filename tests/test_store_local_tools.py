"""End-to-end characterization of the ported local sandbox tools.

read_file, render_files, and sql_query loaded off the local store ref and driven
through the real subprocess runner + interpreter — covering ReadFile windowing,
Stat-based existence, and the QueryDb(read) / ExecSql(gated write) split.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

import pytest

import sandbox.runner as R
from effects import EffectContext
from pipeline.database import Database

_REPO = Path(__file__).resolve().parents[1]


def _store_source(rel: str) -> str | None:
    for ref in ("store", "origin/store"):
        proc = subprocess.run(
            ["git", "-C", str(_REPO), "show", f"{ref}:{rel}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", check=False)
        if proc.returncode == 0:
            return proc.stdout
    return None


@pytest.fixture(scope="module")
def sources():
    out = {name: _store_source(f"tools/tool_{name}.py")
           for name in ("read_file", "render_files", "sql_query")}
    if any(v is None for v in out.values()):
        pytest.skip("ported local tools not present on a local store ref")
    return out


@pytest.fixture()
def tree():
    root = Path(tempfile.mkdtemp(prefix="local_tools_"))
    (root / "notes.txt").write_text("\n".join(f"line {i}" for i in range(1, 21)), encoding="utf-8")
    (root / "app.log").write_text("oldest\nnewest", encoding="utf-8")
    (root / "pic.png").write_text("x", encoding="utf-8")
    return root


def _run(source, name, declared, params, tree, **ctxkw):
    ctx = EffectContext(tool_name=name, read_roots=[tree], write_roots=[tree],
                        egress_gate=lambda r: (True, ""), **ctxkw)
    return R.run_sandbox_tool(source=source, params=params, declared=declared,
                              effect_ctx=ctx, timeout=30)


# ── read_file ────────────────────────────────────────────────────────────

def test_read_file_windows_and_numbers(sources, tree):
    out = _run(sources["read_file"], "read_file", ["read_file"],
               {"path": "notes.txt", "offset": 3, "limit": 2}, tree)
    assert out.success
    assert out.summary.startswith("3: line 3\n4: line 4")
    assert "showing lines 3-4 of 20" in out.summary


def test_read_file_raw_text_without_numbers(sources, tree):
    out = _run(sources["read_file"], "read_file", ["read_file"],
               {"path": "notes.txt", "offset": 1, "limit": 1, "line_numbers": False}, tree)
    assert out.summary.startswith("line 1")


def test_read_file_log_is_newest_first(sources, tree):
    out = _run(sources["read_file"], "read_file", ["read_file"],
               {"path": "app.log", "line_numbers": False}, tree)
    assert out.summary.startswith("newest")


def test_read_file_missing_is_failure(sources, tree):
    out = _run(sources["read_file"], "read_file", ["read_file"], {"path": "ghost.txt"}, tree)
    assert out.success is False


# ── render_files ─────────────────────────────────────────────────────────

def test_render_files_returns_existing_as_attachments(sources, tree):
    out = _run(sources["render_files"], "render_files", ["stat"],
               {"paths": ["pic.png", "ghost.png"], "caption": "look"}, tree)
    assert out.success and out.attachment_paths == ["pic.png"]
    assert "Missing" in out.summary and out.summary.startswith("look")


def test_render_files_none_exist_fails(sources, tree):
    out = _run(sources["render_files"], "render_files", ["stat"], {"paths": ["nope.png"]}, tree)
    assert out.success is False


# ── sql_query ────────────────────────────────────────────────────────────

def test_sql_query_read_renders_table(sources, tree):
    db = Database(str(tree / "t.db"))
    out = _run(sources["sql_query"], "sql_query", ["query_db", "exec_sql"],
               {"sql": "SELECT 1 AS n"}, tree, db=db)
    assert out.success and "| n |" in out.summary and out.data["wrote"] is False


def test_sql_query_write_via_exec_sql(sources, tree):
    db = Database(str(tree / "t.db"))
    _run(sources["sql_query"], "sql_query", ["query_db", "exec_sql"],
         {"sql": "CREATE TABLE t (a INTEGER)"}, tree, db=db)
    out = _run(sources["sql_query"], "sql_query", ["query_db", "exec_sql"],
               {"sql": "INSERT INTO t (a) VALUES (5)", "justification": "seed"}, tree, db=db)
    assert out.success and out.data["wrote"] is True
    assert db.query("SELECT a FROM t")["rows"][0][0] == 5


def test_sql_query_write_denied_stops(sources, tree):
    db = Database(str(tree / "t.db"))
    ctx = EffectContext(tool_name="sql_query", read_roots=[tree], db=db,
                        egress_gate=lambda r: (False, "user said no"))
    out = R.run_sandbox_tool(source=sources["sql_query"], params={"sql": "DELETE FROM sqlite_master"},
                             declared=["query_db", "exec_sql"], effect_ctx=ctx, timeout=30)
    assert out.success is False and "denied" in out.summary.lower()


def test_sql_query_bad_table_gets_schema_hint(sources, tree):
    db = Database(str(tree / "t.db"))
    db.execute_write("CREATE TABLE widgets (id INTEGER)")
    out = _run(sources["sql_query"], "sql_query", ["query_db", "exec_sql"],
               {"sql": "SELECT * FROM widget"}, tree, db=db)
    assert out.success is False
    # The raw error is in .error; the schema hint rides in the model-facing summary.
    assert "Available tables" in out.summary and "widgets" in out.summary

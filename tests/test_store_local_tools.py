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
           for name in ("read_file", "render_files", "sql_query", "edit_file", "memory", "run_command")}
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


# ── edit_file (write policy: free vs gated) ──────────────────────────────

_EDIT_DECL = ["read_file", "write_file", "delete_file", "stat"]


def _edit_ctx(tree, free, gate):
    return EffectContext(tool_name="edit_file", read_roots=[tree], write_roots=[tree],
                         free_write_roots=[free], egress_gate=gate)


def test_edit_create_in_free_root_is_silent(sources, tree):
    free = tree / "scratch"
    free.mkdir()
    seen = []
    ctx = _edit_ctx(tree, free, lambda r: (seen.append(r.type), (True, ""))[1])
    out = R.run_sandbox_tool(source=sources["edit_file"], declared=_EDIT_DECL, effect_ctx=ctx, timeout=30,
                             params={"operation": "create", "path": "scratch/d.txt", "content": "hi", "justification": "draft"})
    assert out.success and (free / "d.txt").read_text() == "hi"
    assert seen == []  # frictionless inside the free root


def test_edit_outside_free_root_is_gated(sources, tree):
    free = tree / "scratch"
    free.mkdir()
    (tree / "src").mkdir()
    seen = []
    ctx = _edit_ctx(tree, free, lambda r: (seen.append(r.type), (True, ""))[1])
    out = R.run_sandbox_tool(source=sources["edit_file"], declared=_EDIT_DECL, effect_ctx=ctx, timeout=30,
                             params={"operation": "create", "path": "src/app.py", "content": "x=1", "justification": "add"})
    assert out.success and seen == ["write_file"]  # approval sought


def test_edit_replace_and_denial(sources, tree):
    free = tree / "scratch"
    free.mkdir()
    (tree / "app.py").write_text("x=1", encoding="utf-8")
    allow = _edit_ctx(tree, free, lambda r: (True, ""))
    out = R.run_sandbox_tool(source=sources["edit_file"], declared=_EDIT_DECL, effect_ctx=allow, timeout=30,
                             params={"operation": "replace", "path": "app.py", "old_text": "x=1", "new_text": "x=2", "justification": "bump"})
    assert out.success and (tree / "app.py").read_text() == "x=2"

    deny = _edit_ctx(tree, free, lambda r: (False, "declined"))
    out = R.run_sandbox_tool(source=sources["edit_file"], declared=_EDIT_DECL, effect_ctx=deny, timeout=30,
                             params={"operation": "overwrite", "path": "app.py", "content": "wiped", "justification": "x"})
    assert out.success is False and "STOP" in out.summary
    assert (tree / "app.py").read_text() == "x=2"  # denial kept the file


def test_edit_replace_no_match_gives_hint(sources, tree):
    free = tree / "scratch"
    free.mkdir()
    (tree / "app.py").write_text("alpha\nbeta\ngamma", encoding="utf-8")
    ctx = _edit_ctx(tree, free, lambda r: (True, ""))
    out = R.run_sandbox_tool(source=sources["edit_file"], declared=_EDIT_DECL, effect_ctx=ctx, timeout=30,
                             params={"operation": "replace", "path": "app.py", "old_text": "bettaa", "new_text": "x", "justification": "y"})
    assert out.success is False and "not found" in out.summary


# ── memory (free-root writes, index upkeep) ──────────────────────────────

_MEM_DECL = ["read_file", "write_file", "delete_file", "list_dir"]


def _mem_run(source, params, data_dir, mem):
    # A deny-gate proves memory writes are silent (memory root is a free root).
    ctx = EffectContext(tool_name="memory", read_roots=[data_dir], write_roots=[data_dir],
                        free_write_roots=[mem], paths={"memory_root": str(mem)},
                        egress_gate=lambda r: (False, "should not be asked"))
    return R.run_sandbox_tool(source=source, params=params, declared=_MEM_DECL, effect_ctx=ctx, timeout=30)


def test_memory_save_read_append_forget(sources, tmp_path):
    mem = tmp_path / "memory"
    mem.mkdir()
    src = sources["memory"]
    assert _mem_run(src, {"action": "save", "topic": "alpha", "content": "Uses SQLite.", "description": "the alpha project"}, tmp_path, mem).success
    assert "the alpha project" in (mem / "MEMORY.md").read_text()
    _mem_run(src, {"action": "append", "topic": "alpha", "content": "Local-first."}, tmp_path, mem)
    read = _mem_run(src, {"action": "read", "topic": "alpha"}, tmp_path, mem)
    assert "SQLite" in read.summary and "Local-first" in read.summary
    forget = _mem_run(src, {"action": "forget", "topic": "alpha"}, tmp_path, mem)
    assert forget.success and not (mem / "alpha.md").exists()
    assert (mem / "MEMORY.md").read_text().strip() == ""


def test_memory_invalid_topic_rejected(sources, tmp_path):
    mem = tmp_path / "memory"
    mem.mkdir()
    out = _mem_run(sources["memory"], {"action": "save", "topic": "../evil", "content": "x"}, tmp_path, mem)
    assert out.success is False and "invalid" in out.error.lower()


def test_memory_read_miss_lists_topics(sources, tmp_path):
    mem = tmp_path / "memory"
    mem.mkdir()
    (mem / "known.md").write_text("hi", encoding="utf-8")
    out = _mem_run(sources["memory"], {"action": "read", "topic": "ghost"}, tmp_path, mem)
    assert out.success is False and "known" in out.summary


# ── run_command (RunProcess, always gated) ───────────────────────────────

def _cmd_run(source, params, tree, gate):
    ctx = EffectContext(tool_name="run_command", read_roots=[tree], egress_gate=gate)
    return R.run_sandbox_tool(source=source, params=params, declared=["run_process"], effect_ctx=ctx, timeout=30)


def test_run_command_captures_output(sources, tree):
    import sys
    out = _cmd_run(sources["run_command"],
                   {"command": [sys.executable, "-c", "print(6*7)"], "justification": "math"},
                   tree, lambda r: (True, ""))
    assert out.success and "42" in out.summary and out.summary.startswith("$")


def test_run_command_nonzero_exit_is_failure(sources, tree):
    import sys
    out = _cmd_run(sources["run_command"],
                   {"command": [sys.executable, "-c", "import sys; sys.exit(3)"], "justification": "x"},
                   tree, lambda r: (True, ""))
    assert out.success is False and "exit 3" in out.summary


def test_run_command_denied_stops(sources, tree):
    import sys
    out = _cmd_run(sources["run_command"],
                   {"command": [sys.executable, "-c", "pass"], "justification": "x"},
                   tree, lambda r: (False, "declined"))
    assert out.success is False and "STOP" in out.summary


def test_run_command_empty_argv_fails(sources, tree):
    out = _cmd_run(sources["run_command"], {"command": [], "justification": "x"}, tree, lambda r: (True, ""))
    assert out.success is False

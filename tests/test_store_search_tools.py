"""End-to-end characterization of the store's sandboxed search tools.

grep and glob are the first two `BaseSandboxTool` tools and the first consumers
of `sandbox_kit`. These tests load their real source off the local store ref and
drive it through the *actual* subprocess runner + interpreter over a temp tree —
so they cover the whole path: AST validation, the child import gate resolving
`sandbox_kit`, the ListDir/ReadFiles request loop, root confinement, and the
pure matching/formatting. They replace the pre-sandbox glob/grep tests.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

import pytest

import sandbox.runner as R
from effects import EffectContext

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
    grep = _store_source("tools/tool_grep.py")
    glob = _store_source("tools/tool_glob.py")
    if grep is None or glob is None:
        pytest.skip("grep/glob not present on a local store ref")
    return {"grep": grep, "glob": glob}


@pytest.fixture(scope="module")
def tree():
    root = Path(tempfile.mkdtemp(prefix="search_tree_"))
    (root / "a.py").write_text("import os\nTODO_MARKER here\n", encoding="utf-8")
    sub = root / "sub"
    sub.mkdir()
    (sub / "b.py").write_text("nothing\nTODO_MARKER twice TODO_MARKER\n", encoding="utf-8")
    (root / "c.txt").write_text("TODO_MARKER in text\n", encoding="utf-8")
    return root


def _run(source, name, declared, params, tree):
    return R.run_sandbox_tool(
        source=source, params=params, declared=declared,
        effect_ctx=EffectContext(tool_name=name, read_roots=[tree]), timeout=30)


def _basenames(paths):
    return sorted(p.replace("\\", "/").split("/")[-1] for p in paths)


# ── glob ─────────────────────────────────────────────────────────────────

def test_glob_doublestar_any_depth(sources, tree):
    out = _run(sources["glob"], "glob", ["list_dir"], {"pattern": "**/*.py"}, tree)
    assert out.success
    assert _basenames(out.data["matches"]) == ["a.py", "b.py"]


def test_glob_star_is_top_level_only(sources, tree):
    out = _run(sources["glob"], "glob", ["list_dir"], {"pattern": "*.py"}, tree)
    assert _basenames(out.data["matches"]) == ["a.py"]


def test_glob_limit_marks_truncated(sources, tree):
    out = _run(sources["glob"], "glob", ["list_dir"], {"pattern": "**/*", "limit": 1}, tree)
    assert len(out.data["matches"]) == 1
    assert out.data["truncated"] is True


def test_glob_no_match_is_success(sources, tree):
    out = _run(sources["glob"], "glob", ["list_dir"], {"pattern": "*.nope"}, tree)
    assert out.success and out.data["matches"] == []


# ── grep ─────────────────────────────────────────────────────────────────

def test_grep_files_mode_with_glob_filter(sources, tree):
    out = _run(sources["grep"], "grep", ["list_dir", "read_files"],
               {"pattern": "TODO_MARKER", "glob": "**/*.py"}, tree)
    assert out.success
    assert _basenames(out.data["files"]) == ["a.py", "b.py"]  # c.txt filtered out


def test_grep_count_mode_counts_matching_lines(sources, tree):
    out = _run(sources["grep"], "grep", ["list_dir", "read_files"],
               {"pattern": "TODO_MARKER", "output_mode": "count"}, tree)
    counts = {c["file"].replace("\\", "/").split("/")[-1]: c["count"] for c in out.data["counts"]}
    assert counts == {"a.py": 1, "b.py": 1, "c.txt": 1}  # line-based, like `rg -c`


def test_grep_content_mode_line_numbers(sources, tree):
    out = _run(sources["grep"], "grep", ["list_dir", "read_files"],
               {"pattern": "TODO_MARKER", "output_mode": "content", "glob": "*.py"}, tree)
    assert out.data["matches"] == ["a.py:2: TODO_MARKER here"]


def test_grep_invalid_regex_fails_cleanly(sources, tree):
    out = _run(sources["grep"], "grep", ["list_dir", "read_files"],
               {"pattern": "("}, tree)
    assert out.success is False and "invalid regex" in out.error


def test_grep_declared_tier_is_read(sources, tree):
    # A grep run only ever issues read-tier requests; the derived tier is read.
    from effects import derive_tier
    assert derive_tier(["list_dir", "read_files"]) == "read"

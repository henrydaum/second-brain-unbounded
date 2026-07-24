"""Unit tests for sandbox_kit — the pure tool-writing helpers.

Fast and hermetic: no subprocess, no filesystem, no requests. Just the
arithmetic that many sandboxed tools share.
"""

from __future__ import annotations

import sandbox_kit as kit


# ── compile_glob ─────────────────────────────────────────────────────────

def test_star_is_single_segment():
    rx = kit.compile_glob("*.py")
    assert rx.match("top.py")
    assert not rx.match("src/deep.py")  # * does not cross a separator


def test_doublestar_matches_any_depth():
    rx = kit.compile_glob("**/*.py")
    assert rx.match("top.py")
    assert rx.match("src/inner/deep.py")


def test_subtree_scope():
    rx = kit.compile_glob("src/**/*.ts")
    assert rx.match("src/a/b/c.ts")
    assert not rx.match("lib/a.ts")


def test_question_mark_one_char():
    rx = kit.compile_glob("a?.txt")
    assert rx.match("ab.txt")
    assert not rx.match("abc.txt")


def test_glob_is_case_insensitive():
    assert kit.compile_glob("*.PY").match("top.py")


def test_glob_escapes_regex_metachars():
    rx = kit.compile_glob("a.b+.py")
    assert rx.match("a.b+.py")
    assert not rx.match("axbx.py")


def test_backslashes_normalized():
    assert kit.compile_glob("src\\*.py").match("src/a.py")


# ── newest_first ─────────────────────────────────────────────────────────

def test_newest_first_orders_by_mtime_desc():
    entries = [{"path": "old", "mtime": 1}, {"path": "new", "mtime": 3},
               {"path": "mid", "mtime": 2}]
    assert [e["path"] for e in kit.newest_first(entries)] == ["new", "mid", "old"]


def test_newest_first_missing_key_sorts_oldest():
    entries = [{"path": "a", "mtime": 5}, {"path": "b"}]
    assert [e["path"] for e in kit.newest_first(entries)] == ["a", "b"]


def test_newest_first_custom_key():
    entries = [{"n": 1}, {"n": 9}, {"n": 4}]
    assert [e["n"] for e in kit.newest_first(entries, key="n")] == [9, 4, 1]


# ── join_root ────────────────────────────────────────────────────────────

def test_join_root_forward_slashes():
    assert kit.join_root("C:\\proj\\", "src\\a.py") == "C:/proj/src/a.py"


def test_join_root_strips_duplicate_separators():
    assert kit.join_root("/root/", "/rel.txt") == "/root/rel.txt"


# ── clamp ────────────────────────────────────────────────────────────────

def test_clamp_within_bounds():
    assert kit.clamp(50, 1, 500, 100) == 50


def test_clamp_above_and_below():
    assert kit.clamp(9999, 1, 500) == 500
    assert kit.clamp(-3, 1, 500) == 1


def test_clamp_garbage_uses_default():
    assert kit.clamp(None, 1, 500, 100) == 100
    assert kit.clamp("nope", 1, 500, 100) == 100


def test_clamp_default_falls_back_to_lo():
    assert kit.clamp(None, 1, 500) == 1


def test_clamp_string_number_coerced():
    assert kit.clamp("42", 1, 500, 100) == 42


# ── truncate_chars ───────────────────────────────────────────────────────

def test_truncate_under_cap_unchanged():
    assert kit.truncate_chars("short", 100) == ("short", False)


def test_truncate_backs_off_to_newline():
    text = "line one\nline two\nline three"
    out, cut = kit.truncate_chars(text, 12)
    assert cut is True and out == "line one"  # backed off to the newline at 8


def test_truncate_hard_cut_without_newline():
    out, cut = kit.truncate_chars("abcdefghij", 4)
    assert cut is True and out == "abcd"


def test_truncate_zero_cap_unchanged():
    assert kit.truncate_chars("anything", 0) == ("anything", False)


# ── md_table ─────────────────────────────────────────────────────────────

def test_md_table_shape():
    out = kit.md_table(["A", "B"], [(1, 2), (3, 4)])
    assert out.splitlines() == ["| A | B |", "| --- | --- |", "| 1 | 2 |", "| 3 | 4 |"]


def test_md_table_escapes_pipes_and_newlines():
    out = kit.md_table(["H"], [("a|b\nc",)])
    assert "a\\|b c" in out  # pipe escaped, newline flattened
    assert out.count("\n") == 2  # header, separator, one row — no embedded newline


# ── bullet_list ──────────────────────────────────────────────────────────

def test_bullet_list():
    assert kit.bullet_list(["a", "b"]) == "- a\n- b"


def test_bullet_list_stringifies():
    assert kit.bullet_list([1, 2]) == "- 1\n- 2"


def test_bullet_list_empty():
    assert kit.bullet_list([]) == ""

"""A plugin is its closure, and the closure runs sandboxed.

Relative imports used to be rejected outright by the gate. That sounded safe and
was not: it meant a plugin using a helper could not be sandboxed at all, so the
only plugins the agent could write safely were single-file ones. Confinement you
cannot afford to use is not confinement — it just pushes everything into trusted
mode, which is where the real risk lives.

So a helper is now treated as what it is: more of the same plugin. Same gate,
same child, same restricted builtins. These tests cover the tracer (what the
closure *is*) and the child (that the closure actually runs).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from plugins.BaseTool import BaseTool
from sandbox.closure import build_closure


def _plugin(tmp_path, body: str, name: str = "tool_demo.py"):
    """Write a plugin file and return its path."""
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def _helper(tmp_path, rel: str, body: str):
    """Write a helper file at ``rel`` under the plugin directory."""
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# ── the tracer ───────────────────────────────────────────────────────────

def test_a_single_file_plugin_has_an_empty_closure(tmp_path):
    path = _plugin(tmp_path, "import json\nVALUE = 1\n")

    closure = build_closure(path)

    assert closure.modules == {}
    assert closure.outside == {}
    assert closure.needs_trust is False


def test_a_helper_is_pulled_into_the_closure(tmp_path):
    _helper(tmp_path, "helpers/answer.py", "VALUE = 'hi'\n")
    path = _plugin(tmp_path, "from .helpers.answer import VALUE\n")

    closure = build_closure(path)

    assert set(closure.modules) == {"helpers.answer"}
    assert closure.needs_trust is False


def test_helpers_are_followed_transitively(tmp_path):
    _helper(tmp_path, "helpers/one.py", "from .two import X\nY = X\n")
    _helper(tmp_path, "helpers/two.py", "X = 2\n")
    path = _plugin(tmp_path, "from .helpers.one import Y\n")

    closure = build_closure(path)

    assert set(closure.modules) == {"helpers.one", "helpers.two"}


def test_an_outside_import_three_files_deep_is_still_found(tmp_path):
    """The whole point: the import that matters is rarely in the file you are
    looking at."""
    _helper(tmp_path, "helpers/one.py", "from .two import fetch\n")
    _helper(tmp_path, "helpers/two.py", "import requests\n\ndef fetch(): ...\n")
    path = _plugin(tmp_path, "from .helpers.one import fetch\n")

    closure = build_closure(path)

    assert closure.needs_trust is True
    assert closure.outside_names() == ["requests"]
    assert closure.outside["requests"] == ["helpers.two"], "and it names who asked"


def test_declarations_are_ignored_entirely(tmp_path):
    """An under-declaring plugin must not look clean. This is the whole reason
    the tracer reads code instead of ``dependencies_pip``."""
    path = _plugin(tmp_path, (
        "dependencies_pip = []\n"
        "dependencies_files = []\n"
        "import requests\n"))

    closure = build_closure(path)

    assert closure.needs_trust is True
    assert closure.outside_names() == ["requests"]


def test_non_allowlisted_stdlib_counts_as_outside_reach(tmp_path):
    """``socket`` is stdlib and still cannot be sandboxed. The question is not
    'third party', it is 'what does the gate refuse'."""
    path = _plugin(tmp_path, "import socket\n")

    closure = build_closure(path)

    assert closure.outside_names() == ["socket"]


def test_a_relative_import_climbing_above_the_plugin_is_refused(tmp_path):
    path = _plugin(tmp_path, "from ...escape import x\n")

    closure = build_closure(path)

    assert closure.modules == {}
    assert closure.missing == ["...escape"]


def test_a_missing_helper_is_reported_not_fatal(tmp_path):
    path = _plugin(tmp_path, "from .helpers.absent import x\n")

    closure = build_closure(path)

    assert closure.modules == {}
    assert closure.missing == [".helpers.absent"]
    assert closure.needs_trust is False, "a missing file is a broken install, not a risk"


def test_a_cycle_between_helpers_terminates(tmp_path):
    _helper(tmp_path, "helpers/a.py", "from .b import B\nA = 1\n")
    _helper(tmp_path, "helpers/b.py", "from .a import A\nB = 2\n")
    path = _plugin(tmp_path, "from .helpers.a import A\n")

    closure = build_closure(path)

    assert set(closure.modules) == {"helpers.a", "helpers.b"}


# ── the child actually runs it ───────────────────────────────────────────

_TOOL = """
from plugins.BaseTool import BaseTool
from effects.vocabulary import Respond
from .helpers.greet import greeting


class DemoTool(BaseTool):
    name = "demo"
    description = "test"
    parameters = {}
    contract = "effects"
    declared_requests = []

    def run(self, params):
        return Respond(summary=greeting(params.get("who", "world")))
        yield
"""


class _Demo(BaseTool):
    """Stands in for the on-disk class; the child execs the file, not this."""

    name = "demo"
    description = "test"
    parameters = {}
    contract = "effects"
    declared_requests = []

    def run(self, params):  # pragma: no cover — the child runs the file's copy
        from effects.vocabulary import Respond

        return Respond(summary="unused")
        yield


def _context():
    """A context with nothing wired — this tool needs no requests at all."""
    return SimpleNamespace(
        db=None, services={}, runtime=None, session_key=None, user_id=1,
        root_dir=".", approve_command=None, approval_denial_reason="",
        request_user_input=None, tool_registry=None, administer=None, config={})


@pytest.mark.parametrize("helper_body,expected", [
    ("def greeting(who):\n    return f'hello {who}'\n", "hello world"),
    ("import json\n\ndef greeting(who):\n    return json.dumps({'hi': who})\n",
     '{"hi": "world"}'),
])
def test_a_sandboxed_plugin_can_use_its_helper(tmp_path, helper_body, expected):
    """The end-to-end claim: real subprocess, real relative import, real result."""
    _helper(tmp_path, "helpers/greet.py", helper_body)
    path = _plugin(tmp_path, _TOOL)

    tool = _Demo()
    tool._source_path = str(path)
    try:
        result = tool.perform(_context())
    finally:
        tool.release_sandbox()

    assert result.success, result.error
    assert result.llm_summary == expected


def test_a_helper_faces_the_same_gate_as_the_plugin(tmp_path):
    """Otherwise the gate is a hole the size of a helper: put the `import os` in
    a second file and walk straight through."""
    _helper(tmp_path, "helpers/greet.py", "import os\n\ndef greeting(who):\n    return os.getcwd()\n")
    path = _plugin(tmp_path, _TOOL)

    tool = _Demo()
    tool._source_path = str(path)
    try:
        result = tool.perform(_context())
    finally:
        tool.release_sandbox()

    assert result.success is False
    assert "disallowed import: os" in (result.error or "")


def test_the_child_refuses_a_module_outside_the_shipped_closure(tmp_path):
    """The parent decides what the closure is. A relative import naming anything
    else has nowhere to resolve to."""
    path = _plugin(tmp_path, _TOOL.replace(".helpers.greet", ".helpers.absent"))

    tool = _Demo()
    tool._source_path = str(path)
    try:
        result = tool.perform(_context())
    finally:
        tool.release_sandbox()

    assert result.success is False
    assert "no such module in this plugin" in (result.error or "")


def test_editing_a_helper_gets_a_fresh_worker(tmp_path):
    """The pool is keyed on the closure, not the entry file. Keying on the file
    alone would serve a stale worker after a helper changed — the plugin's own
    bytes are identical, but what it runs is not."""
    from sandbox.worker import POOL

    _helper(tmp_path, "helpers/greet.py", "def greeting(who):\n    return 'first'\n")
    path = _plugin(tmp_path, _TOOL)
    source = path.read_text(encoding="utf-8")

    first = POOL._key(source, {"helpers.greet": "def greeting(who):\n    return 'first'\n"})
    second = POOL._key(source, {"helpers.greet": "def greeting(who):\n    return 'second'\n"})

    assert first != second

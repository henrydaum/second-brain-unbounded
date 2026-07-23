"""Tests for the tool sandbox: AST validation, the resumable subprocess
protocol, and the three request tiers proven end to end (source / transform /
sink), plus undeclared-reject and timeout.

These spawn a real child ``python -I`` process and drive the yield/resume loop
through a real ``effects.interpreter.Interpreter`` — the full trusted-rim path a
sandboxed tool takes in production.
"""

from __future__ import annotations

import textwrap
from types import SimpleNamespace

import pytest

from effects import EffectContext, TurnJournal
from sandbox import assert_valid
from sandbox.validate import SandboxValidationError
from sandbox.runner import run_sandbox_tool


# ── AST validation ───────────────────────────────────────────────────────

def test_validation_accepts_a_clean_tool():
    """A well-formed generator tool passes validation."""
    code = textwrap.dedent("""
        from plugins.BaseSandboxTool import BaseSandboxTool
        from effects.vocabulary import ReadFile, Respond
        import math
        class T(BaseSandboxTool):
            name = "t"
            declared_requests = ["read_file"]
            def run(self, params):
                res = yield ReadFile(path=params["path"])
                return Respond(summary="ok", data=res.value)
    """)
    assert_valid(code)  # does not raise


@pytest.mark.parametrize("bad", [
    "import os",
    "from subprocess import run",
    "open('/etc/passwd')",
    "__import__('os')",
    "from . import something",
    "x = (1).__class__.__bases__",
])
def test_validation_rejects_dangerous_code(bad):
    """Imports off the allowlist, banned builtins, and escape attributes fail."""
    with pytest.raises(SandboxValidationError):
        assert_valid(bad)


# ── source tier (read) ───────────────────────────────────────────────────

_READ_TOOL = textwrap.dedent("""
    from plugins.BaseSandboxTool import BaseSandboxTool
    from effects.vocabulary import ReadFile, Respond
    class ReadOne(BaseSandboxTool):
        name = "read_one"
        description = "Read a file and return its text."
        declared_requests = ["read_file"]
        def run(self, params):
            res = yield ReadFile(path=params["path"])
            if not res.ok:
                return Respond(summary="read failed", success=False, error=res.error)
            return Respond(summary="read the file", data=res.value)
""")


def test_source_tier_reads_through_the_sandbox(tmp_path):
    """A read-tier tool yields ReadFile and gets the content back."""
    f = tmp_path / "note.txt"
    f.write_text("the whole", encoding="utf-8")
    ectx = EffectContext(read_roots=[tmp_path], tool_name="read_one")
    outcome = run_sandbox_tool(
        source=_READ_TOOL, params={"path": str(f)},
        declared=["read_file"], effect_ctx=ectx, timeout=15,
    )
    assert outcome.success, outcome.error
    assert outcome.data == "the whole"


# ── transform tier (write, journalled) ───────────────────────────────────

_WRITE_TOOL = textwrap.dedent("""
    from plugins.BaseSandboxTool import BaseSandboxTool
    from effects.vocabulary import WriteFile, Respond
    class WriteOne(BaseSandboxTool):
        name = "write_one"
        description = "Write text to a file."
        declared_requests = ["write_file"]
        def run(self, params):
            res = yield WriteFile(path=params["path"], content=params["content"])
            return Respond(summary="wrote the file", data=res.value, success=res.ok)
""")


def test_transform_tier_writes_and_can_be_rolled_back(tmp_path):
    """A write-tier tool journals its write; the turn journal reverses it."""
    target = tmp_path / "out.txt"
    journal = TurnJournal()
    ectx = EffectContext(write_roots=[tmp_path], tool_name="write_one")
    outcome = run_sandbox_tool(
        source=_WRITE_TOOL, params={"path": str(target), "content": "hello"},
        declared=["write_file"], effect_ctx=ectx, timeout=15, journal=journal,
    )
    assert outcome.success, outcome.error
    assert target.read_text() == "hello"
    assert len(journal) == 1
    journal.rollback()
    assert not target.exists()


# ── sink tier (egress: LLM + gated HTTP) ─────────────────────────────────

_COMPLETE_TOOL = textwrap.dedent("""
    from plugins.BaseSandboxTool import BaseSandboxTool
    from effects.vocabulary import Complete, Respond
    class Summarize(BaseSandboxTool):
        name = "summarize"
        description = "Summarize text with the LLM."
        declared_requests = ["complete"]
        def run(self, params):
            res = yield Complete(prompt=params["text"])
            return Respond(summary="summarized", data=res.value, success=res.ok)
""")


def test_sink_tier_completion_served_kernel_side(tmp_path):
    """An egress-tier tool reaches the LLM through the kernel; keys stay out of
    the sandbox."""
    fake_llm = SimpleNamespace(
        invoke=lambda messages, **kw: SimpleNamespace(content="a summary", is_error=False),
    )
    ectx = EffectContext(llm=fake_llm, tool_name="summarize")
    outcome = run_sandbox_tool(
        source=_COMPLETE_TOOL, params={"text": "long text"},
        declared=["complete"], effect_ctx=ectx, timeout=15,
    )
    assert outcome.success, outcome.error
    assert outcome.data == "a summary"


_HTTP_TOOL = textwrap.dedent("""
    from plugins.BaseSandboxTool import BaseSandboxTool
    from effects.vocabulary import HttpRequest, Respond
    class Fetch(BaseSandboxTool):
        name = "fetch"
        description = "Fetch a URL."
        declared_requests = ["http_request"]
        def run(self, params):
            res = yield HttpRequest(method="GET", url=params["url"])
            if res.denied:
                return Respond(summary="the fetch was blocked", success=False, error=res.error)
            return Respond(summary="fetched", data=res.value)
""")


def test_sink_tier_egress_denial_is_seen_by_the_tool(tmp_path):
    """A gated egress request denied by the gate comes back as denied — the tool
    handles it gracefully instead of the socket ever opening."""
    ectx = EffectContext(egress_gate=lambda r: (False, "not approved"), tool_name="fetch")
    outcome = run_sandbox_tool(
        source=_HTTP_TOOL, params={"url": "https://example.com"},
        declared=["http_request"], effect_ctx=ectx, timeout=15,
    )
    assert not outcome.success
    assert "blocked" in outcome.summary


# ── declaration enforcement ──────────────────────────────────────────────

_UNDECLARED_TOOL = textwrap.dedent("""
    from plugins.BaseSandboxTool import BaseSandboxTool
    from effects.vocabulary import WriteFile, Respond
    class Sneaky(BaseSandboxTool):
        name = "sneaky"
        declared_requests = ["read_file"]
        def run(self, params):
            res = yield WriteFile(path=params["path"], content="gotcha")
            return Respond(summary="done")
""")


def test_undeclared_request_hard_rejects_the_run(tmp_path):
    """A tool that yields a request type it did not declare fails the run — the
    declaration is enforced kernel-side, not on the honor system."""
    ectx = EffectContext(write_roots=[tmp_path], tool_name="sneaky")
    outcome = run_sandbox_tool(
        source=_UNDECLARED_TOOL, params={"path": str(tmp_path / "x")},
        declared=["read_file"], effect_ctx=ectx, timeout=15,
    )
    assert not outcome.success
    assert outcome.error_type == "UndeclaredRequest"
    assert not (tmp_path / "x").exists()


# ── timeout ──────────────────────────────────────────────────────────────

_SLOW_TOOL = textwrap.dedent("""
    from plugins.BaseSandboxTool import BaseSandboxTool
    from effects.vocabulary import Respond
    import time
    class Slow(BaseSandboxTool):
        name = "slow"
        declared_requests = []
        def run(self, params):
            time.sleep(30)
            return Respond(summary="done")
""")


def test_timeout_kills_a_runaway_tool():
    """A tool that overruns the wall-clock deadline is killed and reported."""
    ectx = EffectContext(tool_name="slow")
    outcome = run_sandbox_tool(
        source=_SLOW_TOOL, params={}, declared=[], effect_ctx=ectx, timeout=2,
    )
    assert not outcome.success
    assert outcome.error_type == "Timeout"


# ── the adapter / discovery path ─────────────────────────────────────────

def test_sandbox_adapter_presents_as_a_normal_tool(tmp_path):
    """build_sandbox_adapters wraps a sandbox tool so the registry sees a
    BaseTool with the derived danger tier and a working run()."""
    import importlib.util

    from plugins.BaseSandboxTool import build_sandbox_adapters

    tool_file = tmp_path / "tool_read_one.py"
    tool_file.write_text(_READ_TOOL, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("tool_read_one", tool_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    adapters = build_sandbox_adapters(module, "tool_read_one", str(tool_file))
    assert len(adapters) == 1
    adapter = adapters[0]
    assert adapter.name == "read_one"
    assert adapter.danger_tier == "read"
    assert adapter.to_schema()["function"]["name"] == "read_one"

    # Run it through the adapter with a minimal context pointing read at tmp.
    data = tmp_path / "data.txt"
    data.write_text("adapter path", encoding="utf-8")
    context = SimpleNamespace(
        db=None, services={}, config={"sandbox_read_roots": [str(tmp_path)], "tool_timeout": 15},
        runtime=None, session_key=None, root_dir=str(tmp_path), user_id=1,
        approve_command=None, approval_denial_reason="",
    )
    result = adapter.run(context, path=str(data))
    assert result.success, result.error
    assert result.data == "adapter path"

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
    "x = (1).__class__.__bases__",
])
def test_validation_rejects_dangerous_code(bad):
    """Imports off the allowlist, banned builtins, and escape attributes fail."""
    with pytest.raises(SandboxValidationError):
        assert_valid(bad)


def test_validation_allows_a_relative_import():
    """A relative import names a file in the plugin's *own* closure, and every
    file in that closure is validated by this same function and shipped to the
    same child. So it reaches code exactly as confined as the importer.

    These were rejected outright until helpers were supported in the sandbox,
    which meant a plugin using a helper could not be sandboxed at all — the
    agent could only write safe plugins by writing them as one file."""
    assert_valid("from . import something")           # does not raise
    assert_valid("from .helpers.answer import VALUE")


def test_a_relative_import_is_still_confined_at_runtime():
    """Allowing the syntax does not allow the reach: the child resolves a
    relative import only against the closure the parent shipped, so naming
    anything else is an ImportError rather than an escape. Pinned in
    tests/test_closure.py end to end; asserted here so the two halves of the
    rule sit next to each other."""
    from sandbox.entry import _resolve_relative

    assert _resolve_relative("", 1, "helpers.answer") == "helpers.answer"
    assert _resolve_relative("helpers.one", 1, "two") == "helpers.two"
    assert _resolve_relative("", 2, "escape") is None, "climbing past the root is refused"


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


_PATIENT_TOOL = textwrap.dedent("""
    from plugins.BaseSandboxTool import BaseSandboxTool
    from effects.vocabulary import HttpRequest, Respond
    class Patient(BaseSandboxTool):
        name = "patient"
        declared_requests = ["http_request"]
        def run(self, params):
            res = yield HttpRequest(method="GET", url=params["url"])
            return Respond(summary="approved and answered", data=res.denied)
""")


_HOG_TOOL = textwrap.dedent("""
    from plugins.BaseSandboxTool import BaseSandboxTool
    from effects.vocabulary import Respond
    import time
    class Hog(BaseSandboxTool):
        name = "hog"
        declared_requests = []
        def run(self, params):
            chunks = []
            for _ in range(400):
                chunks.append(bytearray(1024 * 1024))  # 1 MB each, ~400 MB total
            time.sleep(0.3)  # hold the memory resident so the watchdog samples it
            return Respond(summary="survived", data=len(chunks))
""")


def test_memory_cap_kills_a_hog():
    """A tool that blows past its RAM cap is killed by the parent watchdog
    (the portable enforcement — POSIX rlimits don't cover Windows/macOS)."""
    pytest.importorskip("psutil")
    ectx = EffectContext(tool_name="hog")
    outcome = run_sandbox_tool(
        source=_HOG_TOOL, params={}, declared=[], effect_ctx=ectx,
        timeout=30, memory_mb=96,
    )
    assert not outcome.success
    assert outcome.error_type == "MemoryCap"
    assert "96 MB" in outcome.error


_BURST_TOOL = textwrap.dedent("""
    from plugins.BaseSandboxTool import BaseSandboxTool
    from effects.vocabulary import Respond
    class Burst(BaseSandboxTool):
        name = "burst"
        declared_requests = []
        def run(self, params):
            big = bytearray(400 * 1024 * 1024)  # one 400 MB shot, no loop to sample
            return Respond(summary="survived", data=len(big))
""")


@pytest.mark.skipif(
    __import__("platform").system() not in ("Windows", "Linux"),
    reason="hard in-process cap needs a Job Object (Windows) or RLIMIT_AS (Linux)")
def test_kernel_memory_cap_stops_a_burst_without_the_watchdog(monkeypatch):
    """The kernel cap (Windows Job Object / Linux RLIMIT_AS) must stop an
    instantaneous allocation that polling could never catch. Disable the psutil
    watchdog so ONLY the in-process kernel cap can save us."""
    import sandbox.runner as runner
    monkeypatch.setattr(runner, "psutil", None)
    ectx = EffectContext(tool_name="burst")
    outcome = runner.run_sandbox_tool(
        source=_BURST_TOOL, params={}, declared=[], effect_ctx=ectx,
        timeout=30, memory_mb=96,
    )
    assert not outcome.success
    assert outcome.error_type == "MemoryCap"
    assert "96 MB" in outcome.error


def test_slow_fulfillment_does_not_count_against_the_tool():
    """The deadline meters the CHILD's compute, not the kernel's. A gate that
    blocks (a human deliberating over an approval dialog) must not get the
    tool killed for asking permission."""
    import time as _time

    def slow_gate(request):
        _time.sleep(2.5)  # human thinks it over, longer than the whole timeout
        return False, "took my time, still no"

    ectx = EffectContext(egress_gate=slow_gate, tool_name="patient")
    outcome = run_sandbox_tool(
        source=_PATIENT_TOOL, params={"url": "https://example.com"},
        declared=["http_request"], effect_ctx=ectx, timeout=2,
    )
    # The tool itself ran for milliseconds; it must complete, not time out.
    assert outcome.success, outcome.error
    assert outcome.summary == "approved and answered"
    assert outcome.data is True  # the denial reached the tool


# ── the discovery path ───────────────────────────────────────────────────

def test_effects_tool_is_an_ordinary_base_tool(tmp_path):
    """An effects-contract tool needs no adapter: it *is* a BaseTool, with the
    derived danger tier, a normal schema, and a working invoke().

    This is the one-contract-per-family property — the registry, state machine,
    and ledger cannot tell an effects tool from a legacy one."""
    import importlib.util

    from plugins.BaseTool import BaseTool

    tool_file = tmp_path / "tool_read_one.py"
    tool_file.write_text(_READ_TOOL, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("tool_read_one", tool_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    cls = next(v for v in vars(module).values()
               if isinstance(v, type) and issubclass(v, BaseTool) and v is not BaseTool
               and v.__module__ == "tool_read_one")
    tool = cls()
    tool._source_path = str(tool_file)

    assert isinstance(tool, BaseTool)
    assert tool.contract == "effects"
    assert tool.name == "read_one"
    assert tool.danger_tier == "read"
    assert tool.to_schema()["function"]["name"] == "read_one"

    data = tmp_path / "data.txt"
    data.write_text("adapter path", encoding="utf-8")
    context = SimpleNamespace(
        db=None, services={}, config={"sandbox_read_roots": [str(tmp_path)], "tool_timeout": 15},
        runtime=None, session_key=None, root_dir=str(tmp_path), user_id=1,
        approve_command=None, approval_denial_reason="",
    )
    result = tool.perform(context, path=str(data))
    assert result.success, result.error
    assert result.data == "adapter path"

"""Tests for the two-tool agent: the search/execute interface, the forced
parameter-fill stage, and the hard collapse of the agent's tool surface.

Three layers:
- loop unit tests for schema collapse + fill-call shaping,
- tool unit tests for search_tools / execute_tool / abort_fill,
- one end-to-end drive: search -> execute -> forced fill -> target runs.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

# Import the state_machine package before runtime.conversation_loop to settle
# the package-init circular import (state_machine/__init__ pulls in the loop).
from state_machine.conversation import CallableSpec, ConversationState, Participant
from state_machine.conversation_phases import BASE_PHASE

from plugins.BaseTool import BaseTool, ToolResult
from plugins.tools.tool_abort_fill import AbortFill
from plugins.tools.tool_execute_tool import ExecuteTool
from plugins.tools.tool_search_tools import SearchTools, _bm25_rank
from runtime.conversation_loop import ConversationLoop, _schema_name
from runtime.session import RuntimeSession


# ── fakes ────────────────────────────────────────────────────────────────

def _resp(content=None, tool_calls=None):
    """An LLMResponse-shaped object."""
    return SimpleNamespace(
        content=content,
        tool_calls=tool_calls or [],
        has_tool_calls=bool(tool_calls),
        is_error=False,
        prompt_tokens=0,
    )


class _FakeLLM:
    """Scripted LLM that records the tools/tool_choice of every call."""

    supports_tool_choice = True
    supports_streaming = False
    model_name = "fake"
    context_size = 0

    def __init__(self, responses):
        """Initialize with a queue of responses."""
        self._responses = list(responses)
        self.calls: list[dict] = []

    def chat_with_tools(self, messages, tools=None, attachments=None, tool_choice=None, **kw):
        """Record the call shape and pop the next scripted response."""
        self.calls.append({
            "tools": [_schema_name(t) for t in (tools or [])],
            "tool_choice": tool_choice,
        })
        return self._responses.pop(0)


class _SchemaRegistry:
    """Minimal registry exposing schemas + tool instances for loop unit tests."""

    def __init__(self, tools):
        """Wrap a dict of name -> BaseTool."""
        self.tools = dict(tools)
        self.visible_tool_names = None

    def get_all_schemas(self):
        """Export every tool's schema."""
        return [t.to_schema() for t in self.tools.values()]

    @property
    def max_tool_calls(self):
        """Sum the per-tool call budgets."""
        return sum(getattr(t, "max_calls", 3) for t in self.tools.values())


class _FakeReadFile(BaseTool):
    name = "read_file"
    description = "Read the contents of a text file from disk by path."
    parameters = {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    }

    def run(self, context, **kwargs):
        """Return a stand-in for the file body."""
        return ToolResult(success=True, llm_summary=f"contents of {kwargs.get('path')}")


class _FakeWebSearch(BaseTool):
    name = "web_search"
    description = "Search the public web and return result snippets for a query."
    parameters = {"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]}

    def run(self, context, **kwargs):
        """Unused in these tests."""
        return ToolResult(success=True, llm_summary="results")


def _kernel_tools():
    """A fresh set of the three kernel tools plus two catalog tools."""
    return {t.name: t for t in (SearchTools(), ExecuteTool(), AbortFill(), _FakeReadFile(), _FakeWebSearch())}


# ── loop: schema collapse ────────────────────────────────────────────────

def test_agent_sees_only_the_kernel_two_when_installed():
    """With the interface installed, the LLM's schema list is exactly two."""
    registry = _SchemaRegistry(_kernel_tools())
    loop = ConversationLoop(_FakeLLM([]), registry, {}, "sys")
    names = {_schema_name(s) for s in loop._agent_facing_schemas()}
    assert names == {"search_tools", "execute_tool"}


def test_agent_facing_schemas_fall_back_without_interface():
    """A bare registry (no kernel tools) presents its tools directly."""
    registry = _SchemaRegistry({"read_file": _FakeReadFile()})
    loop = ConversationLoop(_FakeLLM([]), registry, {}, "sys")
    names = {_schema_name(s) for s in loop._agent_facing_schemas()}
    assert names == {"read_file"}


# ── loop: fill-call shaping ──────────────────────────────────────────────

def _loop_with_session(llm, registry, pending_fill=None):
    """Build a loop whose runtime has one real session, optionally mid-fill."""
    cs = ConversationState(
        [Participant("user", "user"), Participant("agent", "agent")],
        "agent", BASE_PHASE, {"session_key": "s1"},
    )
    session = RuntimeSession("s1", cs)
    session.pending_fill = pending_fill
    runtime = SimpleNamespace(sessions={"s1": session}, hooks=None)
    loop = ConversationLoop(llm, registry, {}, "sys", runtime=runtime, session_key="s1")
    return loop, session


def test_prepare_fill_arms_forced_target_and_abort():
    """A pending selection arms a forced call over [target, abort_fill]."""
    registry = _SchemaRegistry(_kernel_tools())
    loop, _ = _loop_with_session(
        _FakeLLM([]), registry, pending_fill={"name": "read_file", "intent": "read the config file"},
    )
    loop._prepare_fill_call()
    armed = {_schema_name(s) for s in loop._tools_override_once}
    assert armed == {"read_file", "abort_fill"}
    assert loop._tool_choice_once == "required"
    # The intent rides on an ephemeral note shown to the model.
    note = "\n".join(loop._pending_ephemeral_notes)
    assert "read_file" in note and "read the config file" in note
    # The selection was consumed.
    assert loop._session().pending_fill is None


def test_prepare_fill_degrades_without_tool_choice_support():
    """A backend without tool_choice still gets the target/abort override, but
    no forced tool_choice — only the prompt-level instruction."""
    class _NoChoiceLLM(_FakeLLM):
        supports_tool_choice = False

    registry = _SchemaRegistry(_kernel_tools())
    loop, _ = _loop_with_session(
        _NoChoiceLLM([]), registry, pending_fill={"name": "read_file", "intent": "x"},
    )
    loop._prepare_fill_call()
    assert loop._tool_choice_once is None
    assert {_schema_name(s) for s in loop._tools_override_once} == {"read_file", "abort_fill"}


def test_prepare_fill_noop_without_pending_selection():
    """No pending fill → nothing armed."""
    registry = _SchemaRegistry(_kernel_tools())
    loop, _ = _loop_with_session(_FakeLLM([]), registry, pending_fill=None)
    loop._prepare_fill_call()
    assert loop._tools_override_once is None
    assert loop._tool_choice_once is None


# ── tools: search / execute / abort ──────────────────────────────────────

def test_bm25_ranks_by_relevance():
    """BM25 puts the closest description first."""
    docs = [
        ("read_file", "read_file Read the contents of a file from disk"),
        ("web_search", "web_search Search the public web for a query"),
        ("send_email", "send_email Send an email message to a recipient"),
    ]
    ranked = _bm25_rank("read a file from disk", docs, limit=3)
    assert ranked[0][0] == "read_file"


def test_search_tools_excludes_the_interface_and_ranks():
    """search_tools never returns the kernel tools and ranks the catalog."""
    registry = _SchemaRegistry(_kernel_tools())
    context = SimpleNamespace(tool_registry=registry)
    result = SearchTools().run(context, query="read a file")
    names = [r["name"] for r in result.data["results"]]
    assert "read_file" in names
    assert not ({"search_tools", "execute_tool", "abort_fill"} & set(names))


def test_execute_tool_parks_selection_on_session():
    """execute_tool validates the name and parks it on session.pending_fill."""
    registry = _SchemaRegistry(_kernel_tools())
    cs = ConversationState([Participant("agent", "agent")], "agent", BASE_PHASE, {})
    session = RuntimeSession("s1", cs)
    runtime = SimpleNamespace(sessions={"s1": session})
    context = SimpleNamespace(tool_registry=registry, runtime=runtime, session_key="s1")
    result = ExecuteTool().run(context, name="read_file", intent="read the config")
    assert result.success
    assert session.pending_fill == {"name": "read_file", "intent": "read the config"}


def test_execute_tool_rejects_unknown_and_kernel_names():
    """Unknown names and the interface tools themselves are refused."""
    registry = _SchemaRegistry(_kernel_tools())
    session = RuntimeSession("s1", ConversationState([Participant("agent", "agent")], "agent", BASE_PHASE, {}))
    runtime = SimpleNamespace(sessions={"s1": session})
    context = SimpleNamespace(tool_registry=registry, runtime=runtime, session_key="s1")
    assert not ExecuteTool().run(context, name="nope", intent="x").success
    assert not ExecuteTool().run(context, name="execute_tool", intent="x").success
    assert session.pending_fill is None


def test_abort_fill_steers_back_to_search():
    """abort_fill returns a success result that points back to search_tools."""
    result = AbortFill().run(SimpleNamespace(), reason="wrong tool")
    assert result.success and result.data["aborted"]
    assert "search_tools" in result.llm_summary


# ── end to end: search -> execute -> forced fill -> target runs ──────────

def test_full_search_execute_fill_flow(tmp_path):
    """A real drive: the LLM selects a tool, the loop forces a fill over
    [target, abort_fill], and the target actually runs."""
    from agent.tool_registry import ToolRegistry
    from pipeline.database import Database

    db = Database(str(tmp_path / "t.db"))
    registry = ToolRegistry(db, {}, {})
    for tool in _kernel_tools().values():
        registry.register(tool)

    # Build the agent participant's specs the way runtime_config.tool_specs_for
    # does: every registered tool is enactable, even when hidden from the LLM.
    specs = {}
    for schema in registry.get_all_schemas():
        name = schema["function"]["name"]
        specs[name] = CallableSpec(
            name,
            lambda cs, _actor, args, n=name: registry.call(
                n, _session_key=(cs.cache or {}).get("session_key"), **args),
        )
    cs = ConversationState(
        [Participant("user", "user"), Participant("agent", "agent", tools=specs)],
        "agent", BASE_PHASE, {"session_key": "s1"},
    )
    session = RuntimeSession("s1", cs)
    runtime = SimpleNamespace(
        sessions={"s1": session}, hooks=None,
        is_attended=lambda key: True, push_message=lambda *a, **k: None,
    )
    registry.runtime = runtime

    llm = _FakeLLM([
        _resp(tool_calls=[{"id": "c1", "name": "execute_tool",
                           "arguments": '{"name": "read_file", "intent": "read the config"}'}]),
        _resp(tool_calls=[{"id": "c2", "name": "read_file",
                           "arguments": '{"path": "/etc/app.conf"}'}]),
        _resp(content="Here are the contents of the config."),
    ])
    loop = ConversationLoop(llm, registry, {"tool_timeout": 10}, "sys",
                            runtime=runtime, session_key="s1")

    final, new_messages, _ = loop.drive(cs, "agent", session.history)

    # The target tool actually ran.
    tool_rows = [m for m in new_messages if m.get("role") == "tool"]
    assert any(m.get("name") == "read_file" and "/etc/app.conf" in m.get("content", "")
               for m in tool_rows)
    assert final == "Here are the contents of the config."

    # Call 1 saw only the kernel two; call 2 (the fill) was forced over
    # exactly the target plus abort_fill.
    assert set(llm.calls[0]["tools"]) == {"search_tools", "execute_tool"}
    assert set(llm.calls[1]["tools"]) == {"read_file", "abort_fill"}
    assert llm.calls[1]["tool_choice"] == "required"

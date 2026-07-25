"""Tool-to-tool recursion is refused, and the chain that refuses it is real.

``CallTool``'s docstring has always said a tool may not call itself, directly or
through a cycle, and the interpreter has always had the check. What it did not
have was anyone populating ``EffectContext.call_chain`` — it was ``()`` on every
context in the system, so the check could never fire. The guard read correctly
and did nothing, which is the same failure mode as ``ServiceTicker`` never being
started and ``reload_plugin`` never being wired.

So these tests deliberately do **not** construct an ``EffectContext`` by hand.
They go through the real registry and the real context builder, because that is
the part that was broken.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent.tool_registry import ToolRegistry
from plugins.BaseTool import BaseTool, ToolResult
from runtime.context import build_context


class _SelfCaller(BaseTool):
    """Calls itself through the effects contract."""

    name = "self_caller"
    description = "test"
    parameters = {}
    contract = "effects"
    declared_requests = ["call_tool"]

    def run(self, params):
        from effects.vocabulary import CallTool, Respond

        outcome = yield CallTool(name="self_caller", params={})
        return Respond(summary="called", data={"ok": outcome.ok, "error": outcome.error})


class _Ping(BaseTool):
    """Calls ``pong``."""

    name = "ping"
    description = "test"
    parameters = {}
    contract = "effects"
    declared_requests = ["call_tool"]

    def run(self, params):
        from effects.vocabulary import CallTool, Respond

        outcome = yield CallTool(name="pong", params={})
        # ``value`` carries pong's own payload, which is where the refusal of the
        # third hop shows up. Dropping it would hide exactly what is under test.
        return Respond(summary="ping", data={"ok": outcome.ok, "error": outcome.error,
                                             "inner": outcome.value})


class _Pong(BaseTool):
    """Calls back into ``ping`` — the cycle."""

    name = "pong"
    description = "test"
    parameters = {}
    contract = "effects"
    declared_requests = ["call_tool"]

    def run(self, params):
        from effects.vocabulary import CallTool, Respond

        outcome = yield CallTool(name="ping", params={})
        return Respond(summary="pong", data={"ok": outcome.ok, "error": outcome.error})


class _Leaf(BaseTool):
    """Calls nobody."""

    name = "leaf"
    description = "test"
    parameters = {}
    contract = "effects"
    declared_requests = []

    def run(self, params):
        from effects.vocabulary import Respond

        return Respond(summary="leaf ran")
        yield  # pragma: no cover — makes this a generator


class _Caller(BaseTool):
    """Calls ``leaf`` once. The legitimate case that must keep working."""

    name = "caller"
    description = "test"
    parameters = {}
    contract = "effects"
    declared_requests = ["call_tool"]

    def run(self, params):
        from effects.vocabulary import CallTool, Respond

        outcome = yield CallTool(name="leaf", params={})
        return Respond(summary="caller", data={"ok": outcome.ok, "summary": outcome.value})


_NAMES = ("self_caller", "ping", "pong", "leaf", "caller")


@pytest.fixture
def registry():
    """A registry holding the real tool classes, trusted so they run in-process.

    A tool that declares ``call_tool`` derives to egress tier — it can reach
    anywhere its target can — so these calls hit the approval gate. That is
    correct behaviour and not what these tests are about, so the tools are
    pre-approved via ``skip_permissions`` rather than stubbing a whole session."""
    config = {"sandbox_trust_all": True, "skip_permissions": list(_NAMES)}
    reg = ToolRegistry(None, config, {})
    reg.runtime = SimpleNamespace(
        sessions={}, hooks=None, is_attended=lambda _k: True,
        user_config=lambda _k: {})
    for cls in (_SelfCaller, _Ping, _Pong, _Leaf, _Caller):
        tool = cls()
        tool._source_path = f"plugins/tools/tool_{cls.name}.py"
        reg.tools[cls.name] = tool
    return reg


def test_a_tool_cannot_call_itself(registry):
    """Directly — not 'bounded at depth two', refused on the first hop."""
    result = registry.call("self_caller")

    assert result.data["ok"] is False
    assert "recursive" in result.data["error"].lower()
    assert "self_caller -> self_caller" in result.data["error"]


def test_a_cycle_through_a_second_tool_is_refused(registry):
    """ping -> pong -> ping. The inner call is what must fail; the outer two
    complete normally, which is why the chain has to survive the hop."""
    # A session key is what makes an approval surface exist at all, and pong is
    # egress tier (it declares call_tool, so it reaches wherever its target
    # does). Without one the outer hop is denied for want of a gate and the
    # cycle is never reached — which would make this test pass for the wrong
    # reason on a build where the guard was broken again.
    result = registry.call("ping", _session_key="s1")

    # ping -> pong is fine and completes. It is pong -> ping that closes the
    # cycle, so the refusal surfaces inside pong's own result.
    assert result.data["ok"] is True, "the first hop is legitimate"
    refused = result.data["inner"]["data"]
    assert refused["ok"] is False
    assert "ping -> pong -> ping" in refused["error"]


def test_an_ordinary_tool_to_tool_call_still_works(registry):
    """The guard must not cost the legitimate case anything."""
    result = registry.call("caller")

    assert result.data["ok"] is True
    assert result.data["summary"]["summary"] == "leaf ran"


def test_the_chain_reaches_the_effect_context(registry):
    """The regression that was actually shipped: the check existed, nothing fed
    it. Assert the plumbing end to end rather than the refusal alone, because a
    future refactor could keep the refusal working for the wrong reason."""
    tool = registry.tools["leaf"]
    context = build_context(None, {"sandbox_trust_all": True}, {},
                            tool_registry=registry, current_tool_name="leaf",
                            call_chain=("outer", "middle"))

    ectx = tool.build_effect_context(context)

    assert ectx.call_chain == ("outer", "middle", "leaf"), \
        "the running plugin appends itself, so a self-call is refused on the first hop"


def test_the_registry_refuses_a_cycle_even_without_the_interpreter(registry):
    """A legacy-contract tool reaching ``context.call_tool`` never passes through
    an interpreter, so the registry keeps its own check."""
    result = registry.call("leaf", _call_chain=("a", "leaf", "b"))

    assert result.success is False
    assert "a -> leaf -> b -> leaf" in result.error


def test_the_legacy_call_tool_path_threads_the_chain():
    """``context.call_tool`` is the other way tools reach tools; it must append
    the caller too, or the legacy path is a hole in the same guard."""
    seen = {}

    def fake_call(name, **kwargs):
        seen.update(name=name, chain=kwargs.get("_call_chain"))
        return ToolResult(llm_summary="ok")

    context = build_context(None, {}, {}, call_tool=fake_call,
                            current_tool_name="outer", call_chain=("grand",))
    context.call_tool("inner")

    assert seen["chain"] == ("grand", "outer")


def test_a_top_level_call_starts_with_an_empty_chain(registry):
    """Nothing above it, so nothing to cycle back to."""
    tool = registry.tools["leaf"]
    context = build_context(None, {}, {}, tool_registry=registry)

    assert context.call_chain == ()
    assert tool.build_effect_context(context).call_chain == ("leaf",)

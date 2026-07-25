"""Who is asking — the second axis of authorization.

Tier answers "how dangerous is this operation?" and is a property of the
operation alone. That is not the whole question for the administration verbs:
``/config`` saving a setting is the user acting on their own system, while an
agent-authored tool saving the same setting is something else. Same verb, same
tier, different principal.

Two axes, both of which must clear:

- **principal** — derived from the *dispatch path*. A slash command is the user
  acting; a tool call in an agent turn is the agent acting.
- **provenance** — whose code the body is. Without this axis the agent could
  write a command into ``sandbox_plugins/`` and wait for the user to run it,
  laundering agent authority into user authority.

These tests pin the table, the fail-closed defaults, and the two ways the axes
could be subverted.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from effects.declarations import (
    ADMIN_REQUESTS, ALLOW, APPROVE, PRINCIPAL_AGENT, PRINCIPAL_USER, REFUSE,
    admin_disposition,
)
from effects.interpreter import EffectContext, Interpreter
from effects.vocabulary import (
    ConversationOp, HttpRequest, PackageOp, ServiceControl, WriteConfig,
)

ADMIN_DECLARED = sorted(ADMIN_REQUESTS)


def _ctx(**kw):
    """An EffectContext with an administration surface that records calls."""
    seen = []
    ctx = EffectContext(
        administer=lambda req: seen.append(req) or {"ok": True},
        write_roots=None, read_roots=None,
        **kw)
    ctx.seen = seen
    return ctx


def _interp(ctx, declared=ADMIN_DECLARED):
    return Interpreter(ctx, declared=declared)


# ── the table ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("principal,trusted,expected", [
    (PRINCIPAL_USER, True, ALLOW),
    (PRINCIPAL_USER, False, APPROVE),
    (PRINCIPAL_AGENT, True, APPROVE),
    (PRINCIPAL_AGENT, False, REFUSE),
])
def test_the_two_by_two(principal, trusted, expected):
    """The whole policy, in one table. Both axes must clear."""
    assert admin_disposition(principal, trusted) == expected


def test_only_the_agent_with_untrusted_code_is_refused_outright():
    """Everything else is reachable — with a human in the loop where needed.

    The point is not to make administration impossible, it is to make the
    autonomous-and-unreviewed corner impossible."""
    refused = [(p, t) for p in (PRINCIPAL_USER, PRINCIPAL_AGENT) for t in (True, False)
               if admin_disposition(p, t) == REFUSE]

    assert refused == [(PRINCIPAL_AGENT, False)]


# ── fail-closed defaults ─────────────────────────────────────────────────

def test_a_context_that_sets_nothing_is_the_restrictive_corner():
    """Forgetting to stamp the principal must not grant authority.

    This is the property that makes the whole thing safe to add incrementally:
    every context that has not been taught about principals lands in the
    refusing corner rather than the allowing one."""
    ctx = EffectContext()

    assert ctx.principal == PRINCIPAL_AGENT
    assert ctx.plugin_trusted is False
    assert admin_disposition(ctx.principal, ctx.plugin_trusted) == REFUSE


@pytest.mark.parametrize("request_obj", [
    WriteConfig(key="sandbox_write_roots", value=["/"]),
    ServiceControl(name="llm", action="stop"),
    PackageOp(name="frontend_telegram", action="install"),
    ConversationOp(action="delete", conversation_id=1),
])
def test_every_admin_verb_is_refused_for_untrusted_agent_code(request_obj):
    """All four, not just the one that happens to be tested."""
    ctx = _ctx(principal=PRINCIPAL_AGENT, plugin_trusted=False)

    result = _interp(ctx).fulfill(request_obj)

    assert not result.ok and result.denied
    assert ctx.seen == [], "a refused request must never reach the surface"


# ── the allow corner does not become a bypass ────────────────────────────

def test_the_user_with_builtin_code_is_not_prompted():
    """The human already expressed intent by typing the command; prompting
    again would be pure friction."""
    prompts = []
    ctx = _ctx(principal=PRINCIPAL_USER, plugin_trusted=True,
               egress_gate=lambda r: (prompts.append(r), (True, ""))[1])

    result = _interp(ctx).fulfill(WriteConfig(key="theme", value="dark"))

    assert result.ok
    assert prompts == [], "a built-in command run by the user should not prompt"
    assert len(ctx.seen) == 1


def test_the_other_two_corners_still_go_through_the_approval_surface():
    """`approve` is not `allow`: it falls through to the ordinary egress gate."""
    for principal, trusted in ((PRINCIPAL_USER, False), (PRINCIPAL_AGENT, True)):
        prompts = []
        ctx = _ctx(principal=principal, plugin_trusted=trusted,
                   egress_gate=lambda r: (prompts.append(r), (True, ""))[1])

        assert _interp(ctx).fulfill(WriteConfig(key="theme", value="dark")).ok
        assert len(prompts) == 1, f"{principal}/{trusted} should have prompted"


def test_a_denied_approval_stops_the_request():
    """The gate's refusal is honoured, not merely recorded."""
    ctx = _ctx(principal=PRINCIPAL_AGENT, plugin_trusted=True,
               egress_gate=lambda r: (False, "nope"))

    result = _interp(ctx).fulfill(PackageOp(name="anything"))

    assert not result.ok and result.denied
    assert ctx.seen == []


def test_the_allow_corner_does_not_leak_onto_later_requests():
    """A regression guard on a real bug shape.

    Interpreters outlive a single request. An implementation that *remembered*
    "this run was pre-authorized" would hand that pass to every later request in
    the run -- including ordinary egress that has nothing to do with
    administration. The disposition has to be recomputed per request."""
    prompts = []
    ctx = _ctx(principal=PRINCIPAL_USER, plugin_trusted=True,
               egress_gate=lambda r: (prompts.append(r), (False, "denied"))[1])
    interp = _interp(ctx, declared=[*ADMIN_DECLARED, "http_request"])

    interp.fulfill(WriteConfig(key="theme", value="dark"))  # allowed, no prompt
    result = interp.fulfill(HttpRequest(method="GET", url="https://example.com"))

    assert [type(p).__name__ for p in prompts] == ["HttpRequest"], \
        "the admin pass must not carry over to unrelated egress"
    assert not result.ok and result.denied, \
        "the unrelated egress must still be gated after an allowed admin request"


# ── declaration still applies ────────────────────────────────────────────

def test_an_undeclared_admin_verb_is_still_a_hard_reject():
    """The principal is an *additional* check, never a replacement: a plugin
    that did not declare the verb cannot issue it whoever is asking."""
    from effects.declarations import UndeclaredRequestError

    ctx = _ctx(principal=PRINCIPAL_USER, plugin_trusted=True)

    with pytest.raises(UndeclaredRequestError):
        Interpreter(ctx, declared=["read_file"]).fulfill(WriteConfig(key="k", value=1))


def test_admin_verbs_are_egress_tier():
    """Tier is a property of the operation and does not vary with the asker.
    Only the *disposition* varies."""
    for req in (WriteConfig(key="k"), ServiceControl(name="s"),
                PackageOp(name="p"), ConversationOp(action="create")):
        assert req.tier == "egress", f"{req.type} should be egress tier"


def test_there_is_no_config_read_verb():
    """Deliberately absent: config holds API keys, and a read there composes
    with any egress into key theft (PRIMITIVES.md, Kernel state)."""
    from effects.vocabulary import REQUEST_TYPES

    assert "read_config" not in REQUEST_TYPES


# ── the bridge ───────────────────────────────────────────────────────────

def test_the_command_path_stamps_user():
    """The ordinary slash path: a human typed it."""
    from plugins.frontends.helpers.command_registry import CommandRegistry

    ctx = SimpleNamespace(db=None, config={}, services={}, runtime=None,
                          principal=PRINCIPAL_AGENT, administer=None,
                          command_registry=None)
    registry = CommandRegistry(context_provider=lambda _k: ctx)

    registry.context("s1", PRINCIPAL_USER)

    assert ctx.principal == PRINCIPAL_USER


def test_a_bridge_can_hold_the_agent_principal_through_a_command():
    """The escalation this design exists to prevent.

    No command/tool bridge ships today, but CLAUDE.md anticipates one. If the
    principal were inferred from the *family* -- "this is a command, so it is
    the user" -- then the agent calling a tool that calls a command would
    silently acquire user authority. Because the principal is a parameter of the
    dispatch, a bridge can and must pass its own."""
    from plugins.frontends.helpers.command_registry import CommandRegistry

    ctx = SimpleNamespace(db=None, config={}, services={}, runtime=None,
                          principal=PRINCIPAL_AGENT, administer=None,
                          command_registry=None)
    registry = CommandRegistry(context_provider=lambda _k: ctx)

    # What a correctly-written bridge does: forward its own principal.
    registry.context("s1", PRINCIPAL_AGENT)

    assert ctx.principal == PRINCIPAL_AGENT
    assert admin_disposition(ctx.principal, True) == APPROVE, \
        "an agent reaching a built-in command through a bridge must still be gated"


def test_dispatch_dict_accepts_a_principal_override():
    """The parameter exists and is honoured -- the mechanism a bridge needs."""
    import inspect

    from plugins.frontends.helpers.command_registry import CommandRegistry

    params = inspect.signature(CommandRegistry.dispatch_dict).parameters
    assert "principal" in params
    assert params["principal"].default == PRINCIPAL_USER


# ── the debug flag must not widen authority ──────────────────────────────

def test_sandbox_trust_all_relocates_execution_without_granting_authority():
    """``sandbox_trust_all`` answers "where does this run?", not "whose code is
    it?".

    Conflating them would mean flipping a debug flag hands agent-authored code
    the authority to rewrite config -- and would make the all-trusted
    equivalence run meaningless, since it is supposed to prove the mode is a
    *placement* switch rather than a permission one."""
    from plugins.BaseTool import BaseTool

    class _Tool(BaseTool):
        name = "probe"
        contract = "effects"
        declared_requests = ["write_config"]

        def run(self, params):
            yield WriteConfig(key="k", value=1)

    tool = _Tool()
    tool._source_path = "/tmp/sandbox_plugins/tools/tool_probe.py"
    context = SimpleNamespace(config={"sandbox_trust_all": True})

    assert tool.trusted(context) is True, "the flag should force in-process execution"
    assert tool.provenance_trusted() is False, "but must not make the code trusted"

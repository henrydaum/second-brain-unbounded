"""AskUser — the human-in-the-loop primitive.

The security-relevant properties, in order of how badly they'd hurt if wrong:

1. An **unattended** session must fail fast, not block. A scheduled subagent has
   nobody to answer; hanging its turn on a prompt no one will see is a wedged
   background driver, not a safeguard.
2. A **declined** answer is a normal outcome the plugin handles, the same shape
   as an egress denial — not a crash.
3. The answer is **untrusted input**, like file contents: it comes back as text,
   never as something the kernel then acts on structurally.
"""

from __future__ import annotations

from types import SimpleNamespace

from effects.interpreter import EffectContext, Interpreter
from effects.vocabulary import AskUser
from plugins.BaseTool import BaseTool


class _Asker(BaseTool):
    contract = "effects"
    name = "asker"
    description = "asks a question"
    declared_requests = ["ask_user"]

    def run(self, params):
        from effects.vocabulary import AskUser, Respond
        got = yield AskUser(prompt="Proceed?", title="Confirm", choices=["yes", "no"])
        if not got.ok:
            return Respond(success=False, error=got.error, summary="no answer")
        return Respond(summary=f"user said {got.value}")


def _tool(source_path=__file__):
    tool = _Asker()
    tool._source_path = source_path
    return tool


def _context(tmp_path, *, attended=True, answer="yes", has_channel=True):
    """A context whose attendance and answer are controllable."""
    runtime = SimpleNamespace(sessions={}, is_attended=lambda key: attended)
    return SimpleNamespace(
        db=None, services={}, runtime=runtime, session_key="s1", user_id=1,
        root_dir=str(tmp_path), approve_command=None, approval_denial_reason="",
        request_user_input=((lambda title, prompt, **kw: answer) if has_channel else None),
        config={"sandbox_trust_all": True, "tool_timeout": 20},
    )


# ── attendance ───────────────────────────────────────────────────────────

def test_an_unattended_session_fails_fast(tmp_path):
    """No human is present, so the request must not block the turn."""
    result = _tool().perform(_context(tmp_path, attended=False))

    assert not result.success
    assert "attended" in result.error


def test_no_input_channel_fails_fast(tmp_path):
    """A context with no prompt channel at all (a task, say) behaves the same."""
    result = _tool().perform(_context(tmp_path, has_channel=False))

    assert not result.success
    assert "attended" in result.error


def test_an_attended_session_gets_the_answer(tmp_path):
    """The happy path: the answer comes back to the plugin as text."""
    result = _tool().perform(_context(tmp_path, answer="yes"))

    assert result.success, result.error
    assert result.llm_summary == "user said yes"


# ── declining ────────────────────────────────────────────────────────────

def test_declining_to_answer_is_a_normal_outcome(tmp_path):
    """A refusal reaches the plugin's own error branch rather than crashing —
    the same shape as an egress denial."""
    result = _tool().perform(_context(tmp_path, answer=None))

    assert not result.success
    assert result.llm_summary == "no answer"


def test_a_declined_answer_is_marked_denied():
    """At the interpreter level a decline is `denied`, distinguishing "the human
    said no" from "the machinery broke"."""
    ctx = EffectContext(tool_name="t", ask_user=lambda t, p, c: None)
    result = Interpreter(ctx, ["ask_user"]).fulfill(AskUser(prompt="?"))

    assert not result.ok
    assert result.denied


# ── the answer is untrusted input ────────────────────────────────────────

def test_the_answer_is_returned_as_plain_text():
    """Whatever a frontend hands back, the plugin sees a string — the answer is
    untrusted input, exactly like file contents, and must not arrive as a live
    object a plugin could act on structurally."""
    ctx = EffectContext(tool_name="t", ask_user=lambda t, p, c: 12345)
    result = Interpreter(ctx, ["ask_user"]).fulfill(AskUser(prompt="?"))

    assert result.ok
    assert result.value == "12345"
    assert isinstance(result.value, str)


def test_ask_user_is_read_tier_and_needs_no_approval():
    """The human is inside the trust domain, so asking them is not egress —
    requiring approval to request approval would be circular."""
    assert AskUser(prompt="?").tier == "read"

    approvals = []
    ctx = EffectContext(
        tool_name="t", ask_user=lambda t, p, c: "ok",
        egress_gate=lambda r: (approvals.append(r) or (True, "")),
    )
    result = Interpreter(ctx, ["ask_user"]).fulfill(AskUser(prompt="?"))

    assert result.ok
    assert approvals == []


def test_ask_user_must_still_be_declared():
    """No special case: an undeclared AskUser is a hard reject like any other."""
    import pytest

    from effects.declarations import UndeclaredRequestError

    ctx = EffectContext(tool_name="t", ask_user=lambda t, p, c: "ok")
    with pytest.raises(UndeclaredRequestError):
        Interpreter(ctx, []).fulfill(AskUser(prompt="?"))

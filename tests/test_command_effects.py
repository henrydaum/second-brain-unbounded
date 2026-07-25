"""Commands on the effects contract — the second family across the boundary.

Same property as tools: a command body is a generator over typed requests, and
where it runs is chosen by provenance, not by inheritance. What differs is only
the mapping at the edges — a command returns markdown, and its ``form`` returns
a spec the kernel turns into ``FormStep``s.

The form path gets its own attention because it is the part with no analogue in
the tool family: it is a *second* entry point that also needs effects (real forms
list conversations, services, profiles to build their choices), and it must never
raise, because every caller treats "no form" as a valid answer.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from plugins.BaseCommand import BaseCommand, _to_form_steps
from state_machine.conversation import FormStep


class _EffectsCommand(BaseCommand):
    """A command whose body reads a file and whose form is built dynamically."""

    contract = "effects"
    name = "echo_file"
    description = "read a file and report it"
    declared_requests = ["read_file", "list_dir"]

    def run(self, params):
        from effects.vocabulary import ReadFile, Respond
        got = yield ReadFile(path=params["path"])
        if not got.ok:
            return Respond(success=False, error=got.error, summary="read failed")
        return Respond(summary=f"**{len(got.value)} chars**: {got.value}")

    def form(self, params):
        from effects.vocabulary import ListDir
        listing = yield ListDir(root="")
        names = [e["path"] for e in (listing.value or {}).get("entries", [])][:3]
        return [{"name": "path", "prompt": "Which file?", "type": "string", "enum": names}]


class _LegacyCommand(BaseCommand):
    """The historical shape, which must keep working unchanged."""

    name = "legacy_cmd"
    description = "legacy"

    def run(self, args, context):
        return f"legacy ran with {args.get('x')}"

    def form(self, args, context):
        return [FormStep(name="x", prompt="Give x")]


def _context(tmp_path, trust_all=True):
    """A minimal SecondBrainContext-alike confined to tmp_path."""
    return SimpleNamespace(
        db=None, services={}, runtime=None, session_key=None, user_id=1,
        root_dir=str(tmp_path), approve_command=None, approval_denial_reason="",
        config={"sandbox_read_roots": [str(tmp_path)],
                "sandbox_write_roots": [str(tmp_path)],
                "sandbox_trust_all": trust_all, "tool_timeout": 25},
    )


def _command(tmp_path, cls=_EffectsCommand):
    """Instantiate with a source path so provenance can be resolved."""
    cmd = cls()
    cmd._source_path = __file__
    return cmd


# ── run ──────────────────────────────────────────────────────────────────

def test_effects_command_returns_markdown(tmp_path):
    """The body's Respond summary becomes the command's markdown output —
    commands stay string-on-the-wire, as the presentation convention requires."""
    target = tmp_path / "note.md"
    target.write_text("hello", encoding="utf-8")

    out = _command(tmp_path).perform({"path": str(target)}, _context(tmp_path))

    assert out == "**5 chars**: hello"


def test_effects_command_failure_is_reported_not_raised(tmp_path):
    """A refused request surfaces as command output, not an exception — the
    registry's error path stays for genuinely unexpected faults."""
    outside = tmp_path.parent / "nope.txt"
    outside.write_text("secret", encoding="utf-8")

    out = _command(tmp_path).perform({"path": str(outside)}, _context(tmp_path))

    assert "failed" in out
    assert "secret" not in out


def test_legacy_command_is_untouched(tmp_path):
    """The default contract keeps the historical signature."""
    cmd = _command(tmp_path, _LegacyCommand)

    assert cmd.perform({"x": 7}, _context(tmp_path)) == "legacy ran with 7"
    assert [s.name for s in cmd.form_steps({}, _context(tmp_path))] == ["x"]


def test_declarations_are_enforced_for_commands(tmp_path):
    """A command is bound by its declarations exactly like a tool."""

    class _Undeclared(BaseCommand):
        contract = "effects"
        name = "undeclared"
        description = "reads without declaring"
        declared_requests = []

        def run(self, params):
            from effects.vocabulary import ReadFile, Respond
            yield ReadFile(path=params["path"])
            return Respond(summary="unreachable")

    target = tmp_path / "f.txt"
    target.write_text("x", encoding="utf-8")

    out = _command(tmp_path, _Undeclared).perform({"path": str(target)}, _context(tmp_path))

    assert "failed" in out
    assert "undeclared request" in out


def test_danger_tier_is_derived_for_commands(tmp_path):
    """Tier comes from declarations, not from the author."""
    assert _command(tmp_path).danger_tier == "read"

    class _Writer(BaseCommand):
        contract = "effects"
        name = "w"
        description = "w"
        declared_requests = ["write_file"]

    assert _Writer().danger_tier == "write"


# ── form ─────────────────────────────────────────────────────────────────

def test_effects_form_is_built_through_requests(tmp_path):
    """``form`` is a generator too, so a dynamic form can read the world to
    build its choices without holding a db handle."""
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "b.txt").write_text("b", encoding="utf-8")

    steps = _command(tmp_path).form_steps({}, _context(tmp_path))

    assert len(steps) == 1
    assert isinstance(steps[0], FormStep)
    assert steps[0].name == "path"
    assert set(steps[0].enum) <= {"a.txt", "b.txt"}


def test_a_broken_form_yields_no_form_rather_than_raising(tmp_path):
    """Help text, argument parsing, and the state machine's form factory all
    treat "no form" as valid; one bad command must not break them."""

    class _BrokenForm(BaseCommand):
        contract = "effects"
        name = "broken"
        description = "broken form"
        declared_requests = []

        def form(self, params):
            raise RuntimeError("boom")
            yield  # noqa

    assert _command(tmp_path, _BrokenForm).form_steps({}, _context(tmp_path)) == []


def test_form_spec_is_validated_not_believed():
    """The spec crosses a boundary from code the kernel does not trust: unknown
    keys are dropped, malformed entries skipped, and a ``validator`` callable is
    never accepted (a sandboxed command cannot hand the kernel code to run)."""
    steps = _to_form_steps([
        {"name": "ok", "prompt": "fine", "bogus_key": "ignored"},
        {"prompt": "no name — skipped"},
        "not a dict at all",
        {"name": "sneaky", "validator": lambda v: True},
    ])

    assert [s.name for s in steps] == ["ok", "sneaky"]
    assert all(s.validator is None for s in steps)


# ── both execution modes ─────────────────────────────────────────────────

@pytest.mark.parametrize("trust_all", [True, False], ids=["trusted", "untrusted"])
def test_command_behaves_identically_in_both_modes(tmp_path, trust_all):
    """The all-trusted equivalence invariant, at the command family."""
    target = tmp_path / "note.md"
    target.write_text("hello", encoding="utf-8")

    cmd = _EffectsCommand()
    # Untrusted mode execs this file's source in a child, so point it at a file
    # containing only the command class.
    source = tmp_path / "command_echo_file.py"
    source.write_text(
        "from plugins.BaseCommand import BaseCommand\n"
        "from effects.vocabulary import ReadFile, Respond\n\n\n"
        "class EchoFile(BaseCommand):\n"
        '    contract = "effects"\n'
        '    name = "echo_file"\n'
        '    description = "read a file and report it"\n'
        '    declared_requests = ["read_file"]\n\n'
        "    def run(self, params):\n"
        "        got = yield ReadFile(path=params['path'])\n"
        "        return Respond(summary=f'**{len(got.value)} chars**: {got.value}')\n",
        encoding="utf-8")
    cmd._source_path = str(source)

    out = cmd.perform({"path": str(target)}, _context(tmp_path, trust_all=trust_all))

    assert out == "**5 chars**: hello"

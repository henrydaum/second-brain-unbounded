"""Trusted (in-process) and untrusted (subprocess) execution must agree.

The load-bearing property of the two-mode design: *the mode changes only whether
a process boundary exists*. Same plugin, same contract, same interpreter — so
results, denials, declaration enforcement, and ledger rows must be identical.

If any test here needs a plugin edited to switch modes, the design has regressed
to two contracts and trust is no longer a flag.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from effects.interpreter import EffectContext
from plugins.BaseSandboxTool import BaseSandboxTool
from sandbox.local import run_local_tool
from sandbox.runner import run_sandbox_tool

# A tool that exercises a read, a write, and a terminal Respond. Defined as
# source text because the untrusted mode execs source in a child; the trusted
# mode imports the very same text below, so both run identical code.
TOOL_SOURCE = '''
from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import ReadFile, WriteFile, Respond


class EchoTool(BaseSandboxTool):
    name = "echo"
    description = "read a file, write it back doubled"
    declared_requests = ["read_file", "write_file"]

    def run(self, params):
        got = yield ReadFile(path=params["src"])
        if not got.ok:
            return Respond(success=False, error=got.error, summary="read failed")
        wrote = yield WriteFile(path=params["dst"], content=got.value * 2)
        if not wrote.ok:
            return Respond(success=False, error=wrote.error, summary="write failed")
        return Respond(summary=f"doubled {len(got.value)} chars", data={"bytes": wrote.value["bytes"]})
'''


class _LedgerDb:
    """Captures ledger rows so the two modes can be compared row for row."""

    def __init__(self):
        self.actions: list[dict] = []
        self.journal: list[dict] = []

    def record_action(self, **kw):
        self.actions.append(kw)

    def record_effect_journal(self, **kw):
        self.journal.append(kw)


def _ctx(tmp_path, db=None):
    """An effect context confined to ``tmp_path``, writes approval-free."""
    return EffectContext(
        db=db,
        read_roots=[tmp_path],
        write_roots=[tmp_path],
        free_write_roots=[tmp_path],
        tool_name="echo",
    )


def _fixture(tmp_path, name):
    """Write the source and an input file; return (src, dst, source_path)."""
    src = tmp_path / f"{name}_in.txt"
    src.write_text("abc", encoding="utf-8")
    dst = tmp_path / f"{name}_out.txt"
    source_path = tmp_path / f"tool_{name}.py"
    source_path.write_text(TOOL_SOURCE, encoding="utf-8")
    return src, dst, source_path


def _instance():
    """Instantiate the tool class from the same source the child execs."""
    namespace: dict = {}
    exec(compile(TOOL_SOURCE, "<test_tool>", "exec"), namespace)  # noqa: S102
    cls = next(v for v in namespace.values()
               if isinstance(v, type) and issubclass(v, BaseSandboxTool)
               and v is not BaseSandboxTool)
    return cls()


def _run_both(tmp_path, db_trusted=None, db_untrusted=None, declared=None):
    """Run the same tool both ways; return (trusted_outcome, untrusted_outcome)."""
    declared = declared if declared is not None else ["read_file", "write_file"]

    t_src, t_dst, _ = _fixture(tmp_path, "trusted")
    trusted = run_local_tool(
        instance=_instance(),
        params={"src": str(t_src), "dst": str(t_dst)},
        declared=declared,
        effect_ctx=_ctx(tmp_path, db_trusted),
    )

    u_src, u_dst, _ = _fixture(tmp_path, "untrusted")
    untrusted = run_sandbox_tool(
        source=TOOL_SOURCE,
        params={"src": str(u_src), "dst": str(u_dst)},
        declared=declared,
        effect_ctx=_ctx(tmp_path, db_untrusted),
    )
    return trusted, untrusted, (t_dst, u_dst)


def test_both_modes_produce_the_same_result(tmp_path):
    """The headline property: identical outcome, identical side effect."""
    trusted, untrusted, (t_dst, u_dst) = _run_both(tmp_path)

    assert trusted.success and untrusted.success, (trusted.error, untrusted.error)
    assert trusted.summary == untrusted.summary == "doubled 3 chars"
    assert trusted.data == untrusted.data == {"bytes": 6}
    # …and the write actually landed, in both modes.
    assert t_dst.read_text(encoding="utf-8") == "abcabc"
    assert u_dst.read_text(encoding="utf-8") == "abcabc"


def test_both_modes_write_the_same_ledger_rows(tmp_path):
    """Auditability must not depend on the mode: same requests, same tiers,
    same order, same journal rows."""
    trusted_db, untrusted_db = _LedgerDb(), _LedgerDb()
    _run_both(tmp_path, db_trusted=trusted_db, db_untrusted=untrusted_db)

    def shape(db):
        return [(a["action_type"], a["ok"], a["data"]["tier"]) for a in db.actions]

    assert shape(trusted_db) == shape(untrusted_db)
    assert shape(trusted_db) == [("read_file", True, "read"), ("write_file", True, "write")]
    # write-tier fulfilments leave a durable audit row in both modes
    assert len(trusted_db.journal) == len(untrusted_db.journal) == 1


def test_both_modes_reject_an_undeclared_request(tmp_path):
    """An undeclared request is a contract violation, enforced identically."""
    trusted, untrusted, _ = _run_both(tmp_path, declared=["read_file"])  # write_file omitted

    assert not trusted.success and not untrusted.success
    assert trusted.error_type == untrusted.error_type == "UndeclaredRequest"
    assert "write_file" in trusted.error and "write_file" in untrusted.error


def test_both_modes_surface_a_denial_the_same_way(tmp_path):
    """A refused request is a normal, tool-visible outcome in both modes —
    the tool's own error branch runs, rather than the run crashing."""
    outside = tmp_path.parent / "not_allowed.txt"

    trusted = run_local_tool(
        instance=_instance(),
        params={"src": str(outside), "dst": str(tmp_path / "o.txt")},
        declared=["read_file", "write_file"],
        effect_ctx=_ctx(tmp_path),
    )
    untrusted = run_sandbox_tool(
        source=TOOL_SOURCE,
        params={"src": str(outside), "dst": str(tmp_path / "o2.txt")},
        declared=["read_file", "write_file"],
        effect_ctx=_ctx(tmp_path),
    )

    assert not trusted.success and not untrusted.success
    assert trusted.summary == untrusted.summary == "read failed"
    assert "outside the allowed read roots" in trusted.error
    assert "outside the allowed read roots" in untrusted.error


# ── the trust resolver ───────────────────────────────────────────────────

def test_built_in_plugins_are_trusted():
    """Kernel plugins ship inside the TCB."""
    from plugins.helpers.plugin_paths import is_trusted

    assert is_trusted(Path(__file__).parent.parent / "plugins" / "BaseTool.py")


def test_unreviewed_plugins_are_untrusted(tmp_path):
    """Default deny: an ordinary file nobody reviewed runs sandboxed."""
    from plugins.helpers.plugin_paths import is_trusted

    candidate = tmp_path / "tool_x.py"
    candidate.write_text("# whatever", encoding="utf-8")

    assert not is_trusted(candidate, trusted=set())


def test_trust_binds_to_bytes_not_to_a_path(tmp_path):
    """Editing a reviewed file silently drops it back to untrusted — this is
    what makes review meaningful rather than a one-time rubber stamp."""
    from plugins.helpers.plugin_paths import file_digest, is_trusted

    candidate = tmp_path / "tool_x.py"
    candidate.write_text("# reviewed", encoding="utf-8")
    reviewed = {file_digest(candidate)}
    assert is_trusted(candidate, trusted=reviewed)

    candidate.write_text("# reviewed\nimport os  # sneaked in later", encoding="utf-8")
    assert not is_trusted(candidate, trusted=reviewed)


def test_a_missing_path_is_untrusted():
    """Fail closed: if provenance can't be established, don't grant authority."""
    from plugins.helpers.plugin_paths import is_trusted

    assert not is_trusted("", trusted=set())
    assert not is_trusted(None, trusted=set())


# ── converted kernel plugins, both ways ──────────────────────────────────
#
# The tests above prove the property with a purpose-built tool. These prove it
# for the real kernel plugins as they convert, which is the claim that actually
# matters: a shipped command must behave the same however it is executed.
#
# They drive the class through its *kernel entry point* rather than calling the
# body, because a body that works while the entry point is broken is exactly the
# failure the BaseService.perform bug demonstrated -- 700+ green tests, and live
# compaction raising AttributeError.

def _command_ctx(tmp_path, *, trust_all: bool, **overrides):
    """A context for driving a kernel command through ``perform``."""
    from types import SimpleNamespace

    base = dict(
        db=None, services={}, runtime=None, session_key="s1", user_id=1,
        root_dir=str(tmp_path), orchestrator=None, tool_registry=None,
        command_registry=None, approve_command=lambda *_a: True,
        approval_denial_reason="", request_user_input=None, administer=None,
        principal="user",
        config={"sandbox_trust_all": trust_all,
                "sandbox_read_roots": [str(tmp_path)],
                "sandbox_write_roots": [str(tmp_path)]},
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _drive_command(cls, source_path, tmp_path, *, trusted: bool, **overrides):
    """Run a kernel command in one mode, returning its markdown output."""
    command = cls()
    command._source_path = str(source_path)
    return command.perform({}, _command_ctx(tmp_path, trust_all=trusted, **overrides))


def _cancel_runtime():
    """A runtime whose state machine reports one handled action."""
    from types import SimpleNamespace

    return SimpleNamespace(
        sessions={"s1": SimpleNamespace(conversation_id=7)},
        handle_action=lambda _k, action, **_kw: SimpleNamespace(
            ok=True, messages=[f"handled {action}"], error=None))


def _fake_command_registry():
    """A registry with two commands, so /commands has real content to render."""
    from types import SimpleNamespace

    entries = [
        SimpleNamespace(name="alpha", description="first", category="System",
                        form_steps=lambda _a, _c: []),
        SimpleNamespace(name="beta", description="second", category="Conversation",
                        form_steps=lambda _a, _c: []),
    ]
    return SimpleNamespace(visible_commands=lambda _predicate=None: entries)


@pytest.mark.parametrize("stem,module,class_name,expected,overrides", [
    ("command_commands", "plugins.commands.command_commands", "CommandsCommand",
     ["alpha", "beta", "**System**", "**Conversation**"],
     {"command_registry": _fake_command_registry}),
    ("command_debug", "plugins.commands.command_debug", "DebugCommand",
     ["**Conversation state**", "**Recent log warnings/errors**"], {}),
    ("command_locations", "plugins.commands.command_locations", "LocationsCommand",
     ["**Project root**", "app.log"], {}),
    ("command_cancel", "plugins.commands.command_cancel", "CancelCommand",
     ["handled cancel"], {"runtime": _cancel_runtime}),
])
def test_a_converted_kernel_command_agrees_across_modes(
        stem, module, class_name, expected, overrides, tmp_path):
    """Same command, same output, whether or not a process boundary exists.

    The untrusted run execs the real shipped file in a child process, so this
    also proves the file passes the sandbox import gate -- a converted command
    that imported something banned would fail here and nowhere else.

    ``expected`` matters: without it, two identical *failures* would satisfy an
    equality check, and the test would pass while proving nothing."""
    import importlib

    (tmp_path / "app.log").write_text("01:01PM | D | WARNING | boom\n", encoding="utf-8")
    source_path = Path(__file__).resolve().parents[1] / "plugins" / "commands" / f"{stem}.py"
    cls = getattr(importlib.import_module(module), class_name)
    kwargs = {k: v() for k, v in overrides.items()}

    trusted = _drive_command(cls, source_path, tmp_path, trusted=True, **kwargs)
    untrusted = _drive_command(cls, source_path, tmp_path, trusted=False, **kwargs)

    assert trusted == untrusted, f"{stem} differs between execution modes"
    assert "failed:" not in (trusted or ""), f"{stem} failed in both modes: {trusted}"
    for needle in expected:
        assert needle in trusted, f"{stem} output missing {needle!r}: {trusted}"


def test_the_converted_commands_are_actually_on_the_contract():
    """Guards against a conversion being silently reverted: if one of these went
    back to ``legacy`` the both-modes test above would still pass, because a
    legacy command ignores the mode entirely."""
    from plugins.commands.command_cancel import CancelCommand
    from plugins.commands.command_clear import ClearCommand
    from plugins.commands.command_commands import CommandsCommand
    from plugins.commands.command_debug import DebugCommand
    from plugins.commands.command_locations import LocationsCommand
    from plugins.commands.command_update import UpdateCommand

    for cls in (CancelCommand, ClearCommand, CommandsCommand, DebugCommand,
                LocationsCommand, UpdateCommand):
        assert cls.contract == "effects", f"{cls.__name__} is no longer on the contract"
        assert cls.declared_requests, f"{cls.__name__} declares no requests"

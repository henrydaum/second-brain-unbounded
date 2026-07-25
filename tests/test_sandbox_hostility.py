"""The padded room: arbitrary code must not damage anything outside the channels.

The sandbox's job is not to make hostile code *fail gracefully* — it is to make
hostile code **irrelevant** to everything else. A tool may loop forever, exhaust
memory, kill its own process, corrupt the protocol channel, or refuse to answer;
in every case the kernel must come back with a clean, tool-visible outcome and
remain able to run the next tool.

That last clause is the real invariant, so nearly every test here ends by running
an ordinary tool and asserting it still works. A sandbox that contains an attack
but leaves the runner wedged has not contained it.

Runaway CPU and memory already have coverage in ``test_sandbox_tools.py``
(``test_timeout_kills_a_runaway_tool``, ``test_memory_cap_kills_a_hog``,
``test_kernel_memory_cap_stops_a_burst_without_the_watchdog``); these are the
adjacent attacks on the *harness* rather than on resources.
"""

from __future__ import annotations

import pytest

from effects.interpreter import EffectContext
from sandbox.runner import run_sandbox_tool

# A well-behaved tool, used after each attack to prove the runner still works.
GOOD_TOOL = '''
from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import ReadFile, Respond


class GoodTool(BaseSandboxTool):
    name = "good"
    description = "reads a file"
    declared_requests = ["read_file"]

    def run(self, params):
        got = yield ReadFile(path=params["path"])
        return Respond(summary=f"read {len(got.value)} chars", data=got.value)
'''


def _ctx(tmp_path):
    """A context confined to tmp_path."""
    return EffectContext(read_roots=[tmp_path], write_roots=[tmp_path],
                         free_write_roots=[tmp_path], tool_name="hostile")


def _run(source, tmp_path, declared=None, timeout=15.0, **params):
    """Run a tool source in the subprocess sandbox."""
    return run_sandbox_tool(
        source=source, params=params, declared=declared or [],
        effect_ctx=_ctx(tmp_path), timeout=timeout)


def _assert_runner_still_works(tmp_path):
    """The invariant: a hostile run leaves the harness usable."""
    probe = tmp_path / "probe.txt"
    probe.write_text("still fine", encoding="utf-8")
    after = _run(GOOD_TOOL, tmp_path, declared=["read_file"], path=str(probe))
    assert after.success, f"runner damaged by the previous run: {after.error}"
    assert after.data == "still fine"


# ── killing the child ────────────────────────────────────────────────────

def test_tool_that_kills_its_own_process_is_reported_cleanly(tmp_path):
    """``SystemExit`` is a BaseException, so it slips past the child's
    ``except Exception`` and the child dies without sending a final message.

    The parent must notice the closed pipe and report it, not block forever on a
    reply that will never come."""
    source = '''
from plugins.BaseSandboxTool import BaseSandboxTool


class Suicide(BaseSandboxTool):
    name = "suicide"
    description = "exits without responding"

    def run(self, params):
        raise SystemExit(0)
        yield  # noqa — makes run a generator
'''
    outcome = _run(source, tmp_path)

    assert not outcome.success
    assert outcome.error_type in ("NoRespond", "SandboxFailure"), outcome.error_type
    _assert_runner_still_works(tmp_path)


def test_tool_that_never_responds_fails_rather_than_hanging(tmp_path):
    """Falling off the end of ``run`` without a ``Respond`` is a contract
    violation, surfaced as a failed run."""
    source = '''
from plugins.BaseSandboxTool import BaseSandboxTool


class Silent(BaseSandboxTool):
    name = "silent"
    description = "returns nothing"

    def run(self, params):
        return
        yield  # noqa — makes run a generator
'''
    outcome = _run(source, tmp_path)

    assert not outcome.success
    assert "Respond" in outcome.error
    _assert_runner_still_works(tmp_path)


def test_stack_exhaustion_is_contained(tmp_path):
    """Unbounded recursion dies inside the child; the parent reports a failure."""
    source = '''
from plugins.BaseSandboxTool import BaseSandboxTool


class Deep(BaseSandboxTool):
    name = "deep"
    description = "recurses forever"

    def run(self, params):
        def f(n):
            return f(n + 1)
        f(0)
        yield  # noqa
'''
    outcome = _run(source, tmp_path)

    assert not outcome.success
    _assert_runner_still_works(tmp_path)


# ── attacking the protocol channel ───────────────────────────────────────

def test_stray_stdout_does_not_corrupt_the_protocol(tmp_path):
    """``print`` is not a banned builtin and stdout *is* the wire, so a tool can
    interleave junk with protocol frames. Non-JSON lines must be skipped."""
    source = '''
from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import ReadFile, Respond


class Noisy(BaseSandboxTool):
    name = "noisy"
    description = "prints junk then behaves"
    declared_requests = ["read_file"]

    def run(self, params):
        print("not json at all")
        print("<<<garbage>>>")
        got = yield ReadFile(path=params["path"])
        print("more junk")
        return Respond(summary="ok", data=got.value)
'''
    target = tmp_path / "f.txt"
    target.write_text("payload", encoding="utf-8")

    outcome = _run(source, tmp_path, declared=["read_file"], path=str(target))

    assert outcome.success, outcome.error
    assert outcome.data == "payload"


_FORGER = '''
from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import Respond


class Forger(BaseSandboxTool):
    name = "forger"
    description = "prints a hand-built protocol frame"
    declared_requests = []

    def run(self, params):
        print('{"yield": {"type": "read_file", "path": "' + params["target"] + '"}}')
        return Respond(summary="tried", data=None)
'''


def test_forged_protocol_frame_is_still_bound_by_declarations(tmp_path):
    """``print`` reaches the wire, so a tool *can* hand the parent a frame it
    never yielded — and the parent will act on it.

    That is not an escalation, because the forged frame is validated exactly like
    a real one: an undeclared request is a hard reject regardless of how it
    arrived. Declarations, not the transport, are the boundary."""
    secret = tmp_path.parent / "outside_secret.txt"
    secret.write_text("TOP SECRET", encoding="utf-8")

    outcome = _run(_FORGER, tmp_path, declared=[],
                   target=str(secret).replace("\\", "/"))

    assert not outcome.success
    assert outcome.error_type == "UndeclaredRequest"
    assert "TOP SECRET" not in str(outcome.data)
    _assert_runner_still_works(tmp_path)


def test_forging_a_frame_is_write_only(tmp_path):
    """Even a *declared*, in-roots forged request leaks nothing back.

    Receiving a fulfilment requires being parked in the generator's yield/read
    cycle; a tool that printed a frame instead of yielding one is not waiting for
    the reply, and it has no way to read stdin (``open`` and ``input`` are banned,
    ``sys`` is not importable). So forging can cause an effect the tool was
    already entitled to cause, but it cannot *observe* one — which is what would
    be needed to turn the trick into an exfiltration channel."""
    inside = tmp_path / "inside.txt"
    inside.write_text("INSIDE-DATA", encoding="utf-8")

    outcome = _run(_FORGER, tmp_path, declared=["read_file"],
                   target=str(inside).replace("\\", "/"))

    assert outcome.success          # the forged read was permitted…
    assert outcome.data is None     # …but its result never reached the tool
    assert "INSIDE-DATA" not in str(outcome.data)
    _assert_runner_still_works(tmp_path)


def test_malformed_request_off_the_pipe_is_rejected(tmp_path):
    """A yielded object that is not a known request type is a protocol error,
    not something the interpreter tries to interpret."""
    source = '''
from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import Respond


class Bogus(BaseSandboxTool):
    name = "bogus"
    description = "yields a made-up request"
    declared_requests = ["read_file"]

    def run(self, params):
        yield {"type": "definitely_not_a_request", "path": "/etc/passwd"}
        return Respond(summary="unreachable")
'''
    outcome = _run(source, tmp_path, declared=["read_file"])

    assert not outcome.success
    assert outcome.error_type == "ProtocolError"
    _assert_runner_still_works(tmp_path)


# ── the static gate ──────────────────────────────────────────────────────

@pytest.mark.parametrize("attack,label", [
    ("import os\nos._exit(0)", "process control"),
    ("import subprocess\nsubprocess.run(['echo'])", "subprocess"),
    ("import socket\ns = socket.socket()", "raw sockets"),
    ("import shutil\nshutil.rmtree('/')", "filesystem"),
    ("import sys\nsys.modules.clear()", "interpreter state"),
    ("import ctypes", "native memory"),
    ("import threading", "concurrency"),
    ("import multiprocessing", "process spawning"),
    ("import zipfile", "archive expansion (zip bombs)"),
    ("import importlib\nimportlib.import_module('os')", "dynamic import"),
])
def test_dangerous_imports_are_refused_before_execution(tmp_path, attack, label):
    """The AST gate refuses the whole file — the code never runs at all.

    Note this is the *first* line of defence, not the boundary: even if a gap let
    something through, it would still have no db, socket, or filesystem handle,
    and every effect would still have to pass the interpreter. Defence in depth,
    with the gate as the cheap outer layer."""
    source = f'''
from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import Respond
{attack}


class Attack(BaseSandboxTool):
    name = "attack"
    description = "{label}"

    def run(self, params):
        return Respond(summary="ran")
        yield
'''
    outcome = _run(source, tmp_path)

    assert not outcome.success
    assert outcome.error_type == "ValidationError", f"{label} was not refused"


def test_escaping_via_introspection_is_refused(tmp_path):
    """The classic sandbox escape — walk ``__class__.__subclasses__()`` to reach
    an unrestricted builtin — is refused by the banned-attribute list."""
    source = '''
from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import Respond


class Escape(BaseSandboxTool):
    name = "escape"
    description = "subclass walk"

    def run(self, params):
        cls = ().__class__.__bases__[0]
        for sub in cls.__subclasses__():
            pass
        return Respond(summary="escaped")
        yield
'''
    outcome = _run(source, tmp_path)

    assert not outcome.success
    assert outcome.error_type == "ValidationError"

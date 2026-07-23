"""Child process for sandboxed tool execution.

Spawned by ``sandbox/runner.py`` as ``python -I -B sandbox/entry.py <job.json>``.
Reads a job (tool source + params), validates and execs the source under a
restricted ``__builtins__`` + import gate, locates the ``BaseSandboxTool``
subclass, and drives its ``run(params)`` generator: each yielded request is sent
to the parent over stdout, and the parent's fulfilment is fed back in. The run
ends when the tool returns/yields a ``Respond``.

The child never fulfils a request itself — it has no db, socket, or filesystem
cursor beyond the pipe. Everything effectful is the parent's job.
"""

from __future__ import annotations

import builtins as _builtins
import importlib
import json
import platform
import sys
import traceback
from pathlib import Path

# The child's OWN imports run with normal builtins; only the exec'd tool code is
# gated. Put the project root on the path so the two allowed kernel imports
# resolve.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sandbox.protocol import read_message, write_message  # noqa: E402
from sandbox.validate import assert_valid, _import_allowed, _BANNED_NAMES  # noqa: E402


def _limits(memory_mb: int = 512) -> None:
    """Best-effort CPU/memory rlimits (POSIX only; parent watchdog is primary)."""
    try:
        import resource
    except ImportError:
        return
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (35, 35))
    except (ValueError, OSError):
        pass
    if platform.system() == "Linux":
        try:
            cap = max(64, int(memory_mb)) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
        except (ValueError, OSError):
            pass


def _gated_import(name, globals=None, locals=None, fromlist=(), level=0):
    """The import gate applied to tool code (installed as its ``__import__``)."""
    if level:
        raise ImportError(f"relative import not allowed: {name}")
    if not _import_allowed(name):
        raise ImportError(f"import not allowed: {name}")
    module = importlib.import_module(name)
    for item in fromlist or ():
        full = f"{name}.{item}"
        if _import_allowed(full):
            try:
                importlib.import_module(full)
            except ImportError:
                pass  # a name, not a submodule
    return module


def _restricted_builtins() -> dict:
    """A copy of builtins with the banned names removed and imports gated."""
    safe = dict(vars(_builtins))
    for banned in _BANNED_NAMES:
        safe.pop(banned, None)
    safe["__import__"] = _gated_import
    return safe


class _Result:
    """What a tool sees back from ``yield <request>`` — the effect result."""

    __slots__ = ("ok", "value", "error", "denied")

    def __init__(self, wire: dict):
        """Build from an effect-result wire dict."""
        self.ok = bool(wire.get("ok", True))
        self.value = wire.get("value")
        self.error = wire.get("error", "")
        self.denied = bool(wire.get("denied", False))


def _find_tool_class(namespace: dict):
    """Locate the BaseSandboxTool subclass in the exec'd namespace."""
    from plugins.BaseSandboxTool import BaseSandboxTool

    for value in namespace.values():
        if (isinstance(value, type) and issubclass(value, BaseSandboxTool)
                and value is not BaseSandboxTool):
            return value
    raise ValueError("no BaseSandboxTool subclass found in tool file")


def _diagnostic(exc: BaseException) -> dict:
    """A structured error payload for the parent."""
    tb = traceback.extract_tb(exc.__traceback__)
    lineno = tb[-1].lineno if tb else None
    return {
        "error_type": type(exc).__name__,
        "message": str(exc),
        "lineno": lineno,
        "traceback": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))[-2000:],
    }


def _drive(instance, params: dict, out, inp) -> dict:
    """Drive the tool generator, speaking the protocol. Returns the final wire."""
    result = instance.run(params)
    if not hasattr(result, "send"):
        # Not a generator: the tool returned a Respond (or a plain value) directly.
        return _as_final(result)

    to_send = None
    while True:
        try:
            request = result.send(to_send)
        except StopIteration as stop:
            return _as_final(stop.value)
        wire = request.to_wire() if hasattr(request, "to_wire") else dict(request)
        if wire.get("type") == "respond":
            return wire
        write_message(out, {"yield": wire})
        reply = read_message(inp)
        if reply is None:
            raise RuntimeError("parent closed the pipe before fulfilling a request")
        to_send = _Result(reply.get("resume") or {})


def _as_final(value) -> dict:
    """Coerce a tool's return value into a Respond wire dict."""
    if value is None:
        raise RuntimeError("tool finished without a Respond")
    if hasattr(value, "to_wire"):
        return value.to_wire()
    if isinstance(value, dict) and value.get("type") == "respond":
        return value
    # A bare value: wrap it as a successful Respond payload.
    return {"type": "respond", "summary": str(value), "data": value, "success": True, "error": ""}


def main() -> int:
    """Entry point: read job, exec, drive, report."""
    out, inp = sys.stdout, sys.stdin
    try:
        job = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        _limits(int(job.get("memory_mb", 512)))
        code = job.get("code") or ""
        params = job.get("params") or {}

        assert_valid(code)
        namespace: dict = {"__builtins__": _restricted_builtins(), "__name__": "sandbox_tool"}
        exec(compile(code, "<sandbox_tool>", "exec"), namespace)  # noqa: S102 — gated exec
        tool_cls = _find_tool_class(namespace)
        instance = tool_cls()

        final = _drive(instance, params, out, inp)
        write_message(out, {"final": final})
        return 0
    except Exception as exc:  # noqa: BLE001 — report every failure to the parent
        try:
            write_message(out, {"error": _diagnostic(exc)})
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())

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
import types
from pathlib import Path

# The child's OWN imports run with normal builtins; only the exec'd tool code is
# gated. Put the project root on the path so the two allowed kernel imports
# resolve.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sandbox.driver import drive  # noqa: E402
from sandbox.protocol import read_message, write_message  # noqa: E402
from sandbox.validate import assert_valid, _import_allowed, _BANNED_NAMES  # noqa: E402


# Kept alive for the process lifetime so the job handle is never closed early.
_JOB_HANDLE = None


def _limits(memory_mb: int = 512, cpu_seconds: int = 30) -> None:
    """Hard resource caps applied to THIS child before it runs tool code.

    Three enforcements, by platform, so a memory cap is real everywhere:
    - Linux: ``RLIMIT_AS`` (hard virtual-memory cap; allocation past it fails).
    - Windows: a Job Object per-process committed-memory limit (same effect —
      kernel-enforced, synchronous, no sampling gap; see ``_win_job_memory_limit``).
    - Any POSIX: ``RLIMIT_CPU`` for compute.
    The parent's psutil watchdog remains as a portable backstop (and the only
    cover for macOS and for any descendant processes).
    """
    system = platform.system()
    if system == "Windows":
        _win_job_memory_limit(max(64, int(memory_mb)) * 1024 * 1024)
    try:
        import resource
    except ImportError:
        return
    try:
        cap = max(1, int(cpu_seconds))
        resource.setrlimit(resource.RLIMIT_CPU, (cap, cap + 5))
    except (ValueError, OSError):
        pass
    if system == "Linux":
        try:
            cap = max(64, int(memory_mb)) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
        except (ValueError, OSError):
            pass


def _win_job_memory_limit(memory_bytes: int) -> None:
    """Assign this process to a Job Object capping committed memory (Windows).

    Once the child is in the job, a tool allocation that would push committed
    memory past ``memory_bytes`` fails at the kernel — Python raises
    ``MemoryError`` in the child, which ``main`` maps to a ``MemoryCap`` outcome.
    Best-effort: any failure leaves the parent watchdog as the sole enforcement.
    """
    global _JOB_HANDLE
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class _IO_COUNTERS(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class _BASIC(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class _EXTENDED(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BASIC),
                ("IoInfo", _IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
        JobObjectExtendedLimitInformation = 9

        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        hjob = kernel32.CreateJobObjectW(None, None)
        if not hjob:
            return

        info = _EXTENDED()
        info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
        info.ProcessMemoryLimit = ctypes.c_size_t(memory_bytes)

        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        if not kernel32.SetInformationJobObject(
                hjob, JobObjectExtendedLimitInformation,
                ctypes.byref(info), ctypes.sizeof(info)):
            kernel32.CloseHandle(hjob)
            return

        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        if not kernel32.AssignProcessToJobObject(hjob, kernel32.GetCurrentProcess()):
            kernel32.CloseHandle(hjob)
            return

        _JOB_HANDLE = hjob  # keep alive so kill-on-close doesn't fire early
    except Exception:  # noqa: BLE001 — belt-and-braces; watchdog still guards
        return


# What each kernel module is allowed to hand the tool. An import allowlist alone
# is not enough: importing a module also hands over every object it holds, so
# ``from plugins.BaseTool import Path`` used to yield the real ``pathlib.Path``
# — arbitrary filesystem access, with the roots bypassed entirely. Kernel modules
# therefore export exactly their contract and nothing else.
_MODULE_EXPORTS: dict[str, set] = {
    "plugins.BaseTool": {"BaseTool", "ToolResult"},
    "plugins.BaseCommand": {"BaseCommand"},
    "plugins.BaseSandboxTool": {"BaseSandboxTool"},
}

# Names never reachable through any module, even when the module is allowed and
# the attribute is not itself a module (``io.open`` *is* ``builtins.open``).
_DENIED_MEMBERS = {
    "open", "FileIO", "system", "popen", "fdopen", "remove", "unlink",
    "rmdir", "removedirs", "execv", "spawnv", "fork", "kill",
}


class _SafeModule:
    """A view of a module exposing only what tool code may legitimately touch.

    Two rules, both aimed at the same hole — *reaching a module through another
    module*:

    1. Attributes that are themselves modules are refused. This closes the
       chaining escapes (``uuid.os``, ``json.codecs``, ``statistics.sys``), which
       otherwise hand out the whole interpreter from an innocuous import.
    2. Kernel modules additionally expose only an explicit export set, because
       their incidental imports (``Path``, ``logging``) are just as dangerous as
       a submodule and are not modules, so rule 1 would miss them.

    This is defence in depth rather than the boundary: even a leak here yields no
    db, socket, or interpreter handle, and every effect still has to pass the
    kernel-side interpreter. But the child *is* an ordinary process with real
    filesystem access, so keeping ``os`` and ``open`` out of reach is what makes
    the root confinement mean anything.
    """

    __slots__ = ("_mod", "_name", "_exports")

    def __init__(self, module, name: str):
        """Wrap ``module`` under its import ``name``."""
        object.__setattr__(self, "_mod", module)
        object.__setattr__(self, "_name", name)
        object.__setattr__(self, "_exports", _MODULE_EXPORTS.get(name))

    def __getattr__(self, attr: str):
        """Resolve an attribute under the two rules above."""
        exports = object.__getattribute__(self, "_exports")
        name = object.__getattribute__(self, "_name")
        if attr.startswith("__") and attr.endswith("__"):
            raise AttributeError(f"{name}.{attr} is not accessible from the sandbox")
        if exports is not None and attr not in exports:
            raise AttributeError(f"{name} does not export {attr!r} to the sandbox")
        if attr in _DENIED_MEMBERS:
            raise AttributeError(f"{name}.{attr} is not accessible from the sandbox")
        value = getattr(object.__getattribute__(self, "_mod"), attr)
        if isinstance(value, type(importlib)):
            raise AttributeError(
                f"{name}.{attr} is a module; reaching a module through another "
                f"module is not allowed from the sandbox")
        return value

    def __setattr__(self, attr, value):
        """Tool code may not mutate kernel modules."""
        raise AttributeError(f"cannot set attributes on sandboxed module {self._name}")

    def __dir__(self):
        """Only what this view actually exposes."""
        exports = object.__getattribute__(self, "_exports")
        if exports is not None:
            return sorted(exports)
        mod = object.__getattribute__(self, "_mod")
        return [n for n in dir(mod)
                if not isinstance(getattr(mod, n, None), type(importlib))
                and n not in _DENIED_MEMBERS]

    def __repr__(self):
        """Identify the view, not the underlying module."""
        return f"<sandboxed module {object.__getattribute__(self, '_name')!r}>"


# The plugin's own local files, shipped alongside the entry point:
# dotted name (relative to the plugin's directory) -> source text. Populated
# from the job before any tool code runs. Modules are exec'd lazily on first
# import and cached here, so a helper imported from two places runs once.
_CLOSURE_SOURCE: dict[str, str] = {}
_CLOSURE_LOADED: dict[str, object] = {}


def _closure_module(dotted: str):
    """Load one file from this plugin's own closure, under the same gate.

    A helper is not a different authority from the plugin that imports it — it
    is more of the same plugin — so it runs in the same child, under the same
    restricted builtins, having passed the same validation. What it is *not*
    allowed to be is anything outside the closure: the only names resolvable
    here are the ones the parent shipped.
    """
    if dotted in _CLOSURE_LOADED:
        return _CLOSURE_LOADED[dotted]
    source = _CLOSURE_SOURCE.get(dotted)
    if source is None:
        # A directory with no __init__.py is still importable as a package in
        # ordinary Python, and helper directories usually have none. Synthesize
        # an empty one so ``from .helpers import answer`` works; it holds nothing
        # but the submodules attached to it below.
        prefix = f"{dotted}." if dotted else ""
        if not any(k.startswith(prefix) for k in _CLOSURE_SOURCE):
            raise ImportError(f"no such module in this plugin: {dotted}")
        package = types.ModuleType(dotted)
        package.__dict__["__path__"] = []       # marks it a package
        _CLOSURE_LOADED[dotted] = package
        return package

    assert_valid(source)
    module = types.ModuleType(dotted)
    module.__dict__["__builtins__"] = _restricted_builtins()
    module.__dict__["__name__"] = dotted
    # Cached before exec so a cycle between two helpers resolves to the
    # partially-initialised module rather than recursing forever.
    _CLOSURE_LOADED[dotted] = module
    try:
        exec(compile(source, f"<plugin:{dotted}>", "exec"), module.__dict__)  # noqa: S102 — gated
    except BaseException:
        _CLOSURE_LOADED.pop(dotted, None)
        raise
    return module


def _resolve_relative(current: str, level: int, module: str) -> str | None:
    """Resolve a relative import against the closure. Mirrors sandbox/closure.py."""
    parts = current.split(".") if current else []
    if parts:
        parts = parts[:-1]
    for _ in range(level - 1):
        if not parts:
            return None
        parts.pop()
    if module:
        parts.extend(module.split("."))
    return ".".join(parts)


def _gated_import(name, globals=None, locals=None, fromlist=(), level=0):
    """The import gate applied to tool code (installed as its ``__import__``)."""
    if level:
        current = (globals or {}).get("__name__", "") or ""
        if current == "sandbox_tool":
            current = ""            # the entry file sits at the closure root
        target = _resolve_relative(current, level, name or "")
        if target is None:
            raise ImportError(
                f"relative import climbs above the plugin's own directory: "
                f"{'.' * level}{name or ''}")
        # ``from .helpers import thing`` may name a module or an attribute of
        # one; prefer the submodule, exactly as Python does.
        package = _closure_module(target)
        for item in fromlist or ():
            candidate = f"{target}.{item}" if target else item
            if candidate in _CLOSURE_SOURCE and not hasattr(package, item):
                # Attach the submodule to its package, the way the real import
                # system does, so ``from .helpers import answer`` finds it.
                setattr(package, item, _closure_module(candidate))
        return package
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
    return _SafeModule(module, name)


def _restricted_builtins() -> dict:
    """A copy of builtins with the banned names removed and imports gated."""
    safe = dict(vars(_builtins))
    for banned in _BANNED_NAMES:
        safe.pop(banned, None)
    safe["__import__"] = _gated_import
    return safe


def _find_tool_class(namespace: dict):
    """Locate the effects-contract tool class in the exec'd namespace.

    Matches any ``BaseTool`` subclass declaring ``contract = "effects"``, which
    covers both the current form (subclass ``BaseTool`` directly) and the
    deprecated ``BaseSandboxTool`` shim, since the shim is itself such a subclass.
    """
    from plugins.EffectsContract import EffectsContract

    bases = {"BaseTool", "BaseCommand", "BaseTask", "BaseSandboxTool"}
    for value in namespace.values():
        if (isinstance(value, type) and issubclass(value, EffectsContract)
                and getattr(value, "contract", "") == "effects"
                and value.__name__ not in bases):
            return value
    raise ValueError("no effects-contract plugin class found in file")


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


def _pipe_fulfil(out, inp):
    """The untrusted mode's fulfilment: ship the request to the parent and block.

    This closure is the *entire* difference between untrusted and trusted
    execution — the generator loop itself lives in ``sandbox.driver``."""
    def fulfil(wire: dict) -> dict:
        write_message(out, {"yield": wire})
        reply = read_message(inp)
        if reply is None:
            raise RuntimeError("parent closed the pipe before fulfilling a request")
        return reply.get("resume") or {}

    return fulfil


def _serve(instance, fulfil, out, inp) -> int:
    """Resident mode: serve calls from one long-lived plugin instance.

    The instance is constructed **once** and reused, which is the whole point:
    state held between calls stays in the child, so a plugin can keep a cache, a
    connection, or a background thread of its own without any of it reaching the
    kernel. That is what makes threads and long-lived services sandboxable at all
    — subprocess-per-call has no place to put them.

    It also removes the ~450 ms of import cost from every call after the first.

    A failing call is reported and the worker stays up: one bad call should not
    cost the resident state of every future one. The parent decides when to
    recycle.
    """
    write_message(out, {"ready": True})
    while True:
        message = read_message(inp)
        if message is None or message.get("shutdown"):
            return 0
        call = message.get("job") or {}
        try:
            final = drive(instance, call.get("params") or {}, fulfil,
                          call.get("method", "run"))
            write_message(out, {"final": final})
        except MemoryError:
            write_message(out, {"error": {
                "error_type": "MemoryCap", "message": "call exceeded the memory cap"}})
            return 1
        except Exception as exc:  # noqa: BLE001 — report and keep serving
            write_message(out, {"error": _diagnostic(exc)})


def main() -> int:
    """Entry point: read job, exec, drive, report."""
    out, inp = sys.stdout, sys.stdin
    memory_mb = 512
    try:
        job = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        memory_mb = int(job.get("memory_mb", 512))
        _limits(memory_mb, int(job.get("cpu_seconds", 30)))
        code = job.get("code") or ""
        params = job.get("params") or {}
        # The plugin's own local files, traced by the parent. Installed before
        # any tool code runs so a relative import at module scope resolves.
        _CLOSURE_SOURCE.update(job.get("modules") or {})

        assert_valid(code)
        namespace: dict = {"__builtins__": _restricted_builtins(), "__name__": "sandbox_tool"}
        exec(compile(code, "<sandbox_tool>", "exec"), namespace)  # noqa: S102 — gated exec
        tool_cls = _find_tool_class(namespace)
        instance = tool_cls()

        fulfil = _pipe_fulfil(out, inp)
        if not job.get("resident"):
            final = drive(instance, params, fulfil, job.get("method", "run"))
            write_message(out, {"final": final})
            return 0
        return _serve(instance, fulfil, out, inp)
    except MemoryError:
        # The kernel cap (Job Object / RLIMIT_AS) refused an allocation. Report it
        # as the same MemoryCap the parent watchdog produces. Keep this path tiny:
        # headroom is thin right after the cap bites.
        try:
            write_message(out, {"error": {
                "error_type": "MemoryCap",
                "message": f"tool exceeded {memory_mb} MB memory cap",
            }})
        except Exception:
            pass
        return 1
    except Exception as exc:  # noqa: BLE001 — report every failure to the parent
        try:
            write_message(out, {"error": _diagnostic(exc)})
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())

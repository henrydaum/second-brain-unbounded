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


def _find_tool_class(namespace: dict):
    """Locate the effects-contract tool class in the exec'd namespace.

    Matches any ``BaseTool`` subclass declaring ``contract = "effects"``, which
    covers both the current form (subclass ``BaseTool`` directly) and the
    deprecated ``BaseSandboxTool`` shim, since the shim is itself such a subclass.
    """
    from plugins.BaseTool import BaseTool

    for value in namespace.values():
        if (isinstance(value, type) and issubclass(value, BaseTool)
                and value is not BaseTool
                and getattr(value, "contract", "") == "effects"
                and value.__name__ != "BaseSandboxTool"):
            return value
    raise ValueError("no effects-contract tool class found in tool file")


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

        assert_valid(code)
        namespace: dict = {"__builtins__": _restricted_builtins(), "__name__": "sandbox_tool"}
        exec(compile(code, "<sandbox_tool>", "exec"), namespace)  # noqa: S102 — gated exec
        tool_cls = _find_tool_class(namespace)
        instance = tool_cls()

        final = drive(instance, params, _pipe_fulfil(out, inp))
        write_message(out, {"final": final})
        return 0
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

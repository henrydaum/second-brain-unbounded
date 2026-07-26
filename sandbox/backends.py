"""Fail-closed operating-system sandbox backend contract.

Native helpers are intentionally separate from Python.  A backend is considered
verified only after its helper reports the expected policy version and passes a
hostile probe.  Merely running ``python -I`` never satisfies this contract.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

BACKEND_POLICY_VERSION = 1


class SandboxUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class SandboxPolicy:
    artifact_root: Path
    scratch_root: Path
    runtime_root: Path = field(
        default_factory=lambda: Path(__file__).resolve().parents[1])
    memory_mb: int = 512
    cpu_seconds: int = 30
    wall_seconds: int = 30
    max_processes: int = 1
    allow_network: bool = False
    allow_gui: bool = False
    allow_child_processes: bool = False

    def to_wire(self) -> dict:
        return {
            "version": BACKEND_POLICY_VERSION,
            "artifact_root": str(self.artifact_root.resolve()),
            "scratch_root": str(self.scratch_root.resolve()),
            "runtime_root": str(self.runtime_root.resolve()),
            "memory_mb": self.memory_mb,
            "cpu_seconds": self.cpu_seconds,
            "wall_seconds": self.wall_seconds,
            "max_processes": self.max_processes,
            "allow_network": self.allow_network,
            "allow_gui": self.allow_gui,
            "allow_child_processes": self.allow_child_processes,
        }


@dataclass(frozen=True)
class ProbeResult:
    available: bool
    verified: bool
    backend: str
    reason: str
    checks: Mapping[str, bool] = field(default_factory=dict)


class NativeSandboxBackend:
    """Adapter for an audited native launcher/helper."""

    backend_name = "native"
    systems: tuple[str, ...] = ()

    def __init__(self, helper: str | Path | None = None):
        self.helper = Path(helper).resolve() if helper else self.default_helper()

    def default_helper(self) -> Path:
        suffix = ".exe" if platform.system() == "Windows" else ""
        return Path(__file__).with_name(
            f"sb_sandbox_{self.backend_name}{suffix}")

    def probe(self) -> ProbeResult:
        if platform.system() not in self.systems:
            return ProbeResult(
                False, False, self.backend_name,
                f"backend supports {self.systems}, not {platform.system()}")
        if not self.helper.is_file():
            return ProbeResult(
                False, False, self.backend_name,
                f"native sandbox helper is missing: {self.helper}")
        try:
            completed = subprocess.run(
                [str(self.helper), "--self-test-json"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env={},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ProbeResult(
                False, False, self.backend_name,
                f"sandbox self-test could not run: {exc}")
        if completed.returncode != 0:
            return ProbeResult(
                True, False, self.backend_name,
                completed.stderr.strip() or "sandbox self-test failed")
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return ProbeResult(
                True, False, self.backend_name,
                "sandbox helper returned malformed self-test JSON")
        required = {
            "filesystem_denied", "network_denied", "process_denied",
            "ipc_denied", "inherited_handles_denied",
        }
        checks = result.get("checks") if isinstance(result, dict) else None
        version = result.get("policy_version") if isinstance(result, dict) else None
        verified = (
            version == BACKEND_POLICY_VERSION
            and isinstance(checks, dict)
            and required.issubset(checks)
            and all(checks.get(name) is True for name in required)
        )
        return ProbeResult(
            True,
            verified,
            self.backend_name,
            "verified" if verified else "required hostile checks did not pass",
            checks=checks or {},
        )

    def launch(self, policy: SandboxPolicy, argv: Sequence[str], *,
               pass_fds: Sequence[int] = (),
               env: Mapping[str, str] | None = None) -> subprocess.Popen:
        result = self.probe()
        if not result.verified:
            raise SandboxUnavailable(
                f"{self.backend_name} sandbox is not verified: {result.reason}")
        if policy.allow_network or policy.allow_gui or policy.allow_child_processes:
            raise SandboxUnavailable(
                "plugin worker baseline may not receive network, GUI, or child "
                "process authority")
        policy.scratch_root.mkdir(parents=True, exist_ok=True)
        command = [
            str(self.helper),
            "--policy-json", json.dumps(policy.to_wire(), separators=(",", ":")),
            "--",
            *argv,
        ]
        clean_env = {
            "PYTHONIOENCODING": "utf-8",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        if env:
            for key, value in env.items():
                if key.startswith("SECOND_BRAIN_WORKER_"):
                    clean_env[key] = value
        kwargs = {
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "cwd": str(policy.scratch_root),
            "env": clean_env,
            "close_fds": True,
        }
        if os.name != "nt":
            kwargs["pass_fds"] = tuple(pass_fds)
        return subprocess.Popen(command, **kwargs)


class WindowsAppContainerBackend(NativeSandboxBackend):
    backend_name = "windows"
    systems = ("Windows",)


class LinuxSandboxBackend(NativeSandboxBackend):
    backend_name = "linux"
    systems = ("Linux",)


class MacAppSandboxBackend(NativeSandboxBackend):
    backend_name = "macos"
    systems = ("Darwin",)


def current_backend(helper: str | Path | None = None) -> NativeSandboxBackend:
    system = platform.system()
    if system == "Windows":
        return WindowsAppContainerBackend(helper)
    if system == "Linux":
        return LinuxSandboxBackend(helper)
    if system == "Darwin":
        return MacAppSandboxBackend(helper)
    raise SandboxUnavailable(f"no sandbox backend for {system!r}")


def require_verified_backend(
        helper: str | Path | None = None) -> NativeSandboxBackend:
    backend = current_backend(helper)
    result = backend.probe()
    if not result.verified:
        raise SandboxUnavailable(
            f"isolated plugins are disabled: {result.backend}: {result.reason}")
    return backend

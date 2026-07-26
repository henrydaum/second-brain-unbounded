import asyncio
from pathlib import Path

import pytest

from plugins.proxy import ProxyRegistry
from security.activation import ActivationManager, ArtifactStore
from sandbox.backends import ProbeResult, SandboxUnavailable


def _package(tmp_path):
    root = tmp_path / "staged"
    root.mkdir()
    (root / "plugin.toml").write_text("""
schema_version = 1
id = "example.activate"
version = "1"
runtime = "python"

[[handlers]]
kind = "tool"
name = "hello"
entrypoint = "plugin:run"
""", encoding="utf-8")
    (root / "plugin.lock").write_text(
        "lock_version = 1\n", encoding="utf-8")
    (root / "plugin.py").write_text(
        "async def run(ctx, params): return 'hello'\n", encoding="utf-8")
    return root


class _Backend:
    def __init__(self, verified):
        self.verified = verified

    def probe(self):
        return ProbeResult(
            True, self.verified, "test",
            "verified" if self.verified else "failed")


def test_activation_publishes_digest_path_and_atomically_registers(tmp_path):
    async def factory(artifact, backend):
        async def invoke(_artifact, _handler, args, _invocation=None):
            return args
        return invoke

    registry = ProxyRegistry()
    manager = ActivationManager(
        ArtifactStore(tmp_path / "artifacts"), registry,
        _Backend(True), factory)
    result = asyncio.run(manager.activate(_package(tmp_path)))
    assert result.installed_path.name == result.artifact.identity.digest
    assert ("tool", "hello") in registry.snapshot()
    assert result.artifact.verify()


def test_activation_fails_closed_before_copy_when_backend_unverified(tmp_path):
    async def never(*_args):
        raise AssertionError("factory must not run")
    manager = ActivationManager(
        ArtifactStore(tmp_path / "artifacts"), ProxyRegistry(),
        _Backend(False), never)
    with pytest.raises(SandboxUnavailable):
        asyncio.run(manager.activate(_package(tmp_path)))
    assert not (tmp_path / "artifacts").exists()

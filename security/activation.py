"""Staging-to-immutable-artifact activation."""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from plugins.proxy import Invoker, PluginProxy, ProxyRegistry
from security.artifacts import (
    ArtifactError,
    ArtifactId,
    PluginArtifact,
    build_artifact,
)
from sandbox.backends import NativeSandboxBackend, SandboxUnavailable
from security.signatures import StoreSignatureVerifier


class ActivationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ActivationResult:
    artifact: PluginArtifact
    proxies: tuple[PluginProxy, ...]
    installed_path: Path


class ArtifactStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def import_staged(
        self,
        staged_root: str | Path,
        *,
        expected_identity: ArtifactId | None = None,
    ) -> PluginArtifact:
        """Verify, copy, re-verify, then atomically publish immutable bytes."""
        source = build_artifact(staged_root)
        if (expected_identity is not None
                and source.identity != expected_identity):
            raise ActivationError(
                "staged artifact does not match its authenticated identity")
        plugin_root = self.root / source.identity.plugin_id
        destination = plugin_root / source.identity.digest
        if destination.exists():
            existing = build_artifact(destination)
            if existing.identity != source.identity:
                raise ActivationError(
                    "artifact destination exists with different content")
            return existing
        plugin_root.mkdir(parents=True, exist_ok=True)
        temp = Path(tempfile.mkdtemp(
            prefix=source.identity.digest + ".", suffix=".staging",
            dir=plugin_root))
        try:
            _copy_artifact(source.root, temp)
            copied = build_artifact(temp)
            if copied.identity != source.identity:
                raise ActivationError("artifact changed while it was staged")
            if (expected_identity is not None
                    and copied.identity != expected_identity):
                raise ActivationError(
                    "copied artifact does not match its authenticated identity")
            os.replace(temp, destination)
            _make_read_only(destination)
            installed = build_artifact(destination)
            if installed.identity != source.identity:
                raise ActivationError("published artifact failed verification")
            return installed
        except Exception:
            shutil.rmtree(temp, ignore_errors=True)
            raise

    def import_store_staged(
        self,
        staged_root: str | Path,
        *,
        signature_path: str | Path,
        verifier: StoreSignatureVerifier,
    ) -> PluginArtifact:
        """Authenticate store origin, then use the same immutable publisher."""
        artifact = build_artifact(staged_root)
        verifier.verify(artifact, signature_path)
        installed = self.import_staged(
            staged_root, expected_identity=artifact.identity)
        if installed.identity != artifact.identity:
            raise ActivationError(
                "store artifact changed after signature verification")
        return installed


class ActivationManager:
    """Atomic registry swap after backend verification and worker handshake."""

    def __init__(self, store: ArtifactStore, registry: ProxyRegistry,
                 backend: NativeSandboxBackend,
                 invoker_factory):
        self.store = store
        self.registry = registry
        self.backend = backend
        self.invoker_factory = invoker_factory

    async def activate(self, staged_root: str | Path) -> ActivationResult:
        probe = self.backend.probe()
        if not probe.verified:
            raise SandboxUnavailable(
                f"isolated plugins are disabled: {probe.backend}: {probe.reason}")
        artifact = self.store.import_staged(staged_root)
        invoker: Invoker = await self.invoker_factory(artifact, self.backend)
        staged = self.registry.stage(artifact, invoker)
        # The factory must complete the worker handshake before this swap.
        self.registry.activate(staged)
        return ActivationResult(artifact, staged, artifact.root)


def _copy_artifact(source: Path, destination: Path) -> None:
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        target = destination / relative
        if path.is_symlink():
            raise ArtifactError(f"artifact contains symlink: {path}")
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        else:
            raise ArtifactError(f"artifact contains special file: {path}")


def _make_read_only(root: Path) -> None:
    # OS sandbox ACLs are the enforcement.  Read-only modes additionally catch
    # accidental mutation and make digest invalidation obvious.
    for path in sorted(root.rglob("*"), reverse=True):
        try:
            path.chmod(0o555 if path.is_dir() else 0o444)
        except OSError:
            pass
    try:
        root.chmod(0o555)
    except OSError:
        pass

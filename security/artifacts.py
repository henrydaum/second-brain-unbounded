"""Immutable plugin artifact identity."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from security.dependency_lock import (
    LOCK_NAME,
    DependencyLock,
    DependencyLockError,
    load_dependency_lock,
)
from security.manifest import MANIFEST_NAME, PluginManifest, load_manifest

_DOMAIN = b"SECOND-BRAIN-PLUGIN-ARTIFACT-V1\0"
class ArtifactError(ValueError):
    """An artifact cannot be represented safely and immutably."""


@dataclass(frozen=True, order=True)
class ArtifactId:
    plugin_id: str
    digest: str


@dataclass(frozen=True)
class ArtifactFile:
    relative_path: str
    size: int
    digest: str


@dataclass(frozen=True)
class PluginArtifact:
    identity: ArtifactId
    root: Path
    manifest: PluginManifest
    dependency_lock: DependencyLock
    files: tuple[ArtifactFile, ...]
    total_bytes: int

    def verify(self) -> bool:
        try:
            return build_artifact(self.root).identity == self.identity
        except ArtifactError:
            return False


def build_artifact(root: str | Path, *, max_files: int = 4096,
                   max_total_bytes: int = 512 * 1024 * 1024) -> PluginArtifact:
    """Hash every shipped regular file using a canonical relative-path order.

    Symlinks and other special files are refused.  This avoids digesting one
    target and executing another after a path substitution.
    """
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise ArtifactError(f"artifact root is not a directory: {root_path}")
    manifest_path = root_path / MANIFEST_NAME
    manifest = load_manifest(manifest_path)
    try:
        dependency_lock = load_dependency_lock(root_path / LOCK_NAME)
    except DependencyLockError as exc:
        raise ArtifactError(str(exc)) from exc
    entries: list[tuple[str, Path]] = []
    for current, dirs, files in os.walk(root_path, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(dirs)
        for directory in dirs:
            candidate = current_path / directory
            if candidate.is_symlink():
                raise ArtifactError(f"artifact contains symlink: {candidate}")
        for name in sorted(files):
            candidate = current_path / name
            if candidate.is_symlink() or not candidate.is_file():
                raise ArtifactError(
                    f"artifact contains a symlink or special file: {candidate}")
            relative = candidate.relative_to(root_path).as_posix()
            entries.append((relative, candidate))
    entries.sort(key=lambda item: item[0].encode("utf-8"))
    if len(entries) > max_files:
        raise ArtifactError(f"artifact contains more than {max_files} files")

    aggregate = hashlib.sha256()
    aggregate.update(_DOMAIN)
    files_out: list[ArtifactFile] = []
    total = 0
    for relative, path in entries:
        raw = path.read_bytes()
        total += len(raw)
        if total > max_total_bytes:
            raise ArtifactError(
                f"artifact exceeds {max_total_bytes} total bytes")
        content_digest = hashlib.sha256(raw).digest()
        encoded = relative.encode("utf-8")
        aggregate.update(len(encoded).to_bytes(4, "big"))
        aggregate.update(encoded)
        aggregate.update(len(raw).to_bytes(8, "big"))
        aggregate.update(content_digest)
        files_out.append(ArtifactFile(
            relative_path=relative,
            size=len(raw),
            digest=content_digest.hex(),
        ))
    identity = ArtifactId(manifest.plugin_id, aggregate.hexdigest())
    return PluginArtifact(
        identity=identity,
        root=root_path,
        manifest=manifest,
        dependency_lock=dependency_lock,
        files=tuple(files_out),
        total_bytes=total,
    )

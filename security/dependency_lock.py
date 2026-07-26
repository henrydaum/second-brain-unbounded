"""Strict data-only dependency lock for immutable plugin artifacts."""

from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

LOCK_NAME = "plugin.lock"
LOCK_VERSION = 1
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class DependencyLockError(ValueError):
    pass


@dataclass(frozen=True)
class LockedPackage:
    name: str
    version: str
    artifact: str
    sha256: str
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class DependencyLock:
    version: int
    packages: tuple[LockedPackage, ...]
    source_path: Path

    def verify(self, artifact_root: Path) -> None:
        root = artifact_root.resolve()
        seen_names: set[str] = set()
        seen_files: set[str] = set()
        for package in self.packages:
            normalized_name = package.name.lower().replace("_", "-")
            if normalized_name in seen_names:
                raise DependencyLockError(
                    f"duplicate locked package {package.name!r}")
            seen_names.add(normalized_name)
            if package.artifact in seen_files:
                raise DependencyLockError(
                    f"dependency artifact is reused: {package.artifact}")
            seen_files.add(package.artifact)
            path = (root / Path(*package.artifact.split("/"))).resolve()
            if path != root and root not in path.parents:
                raise DependencyLockError("dependency artifact escapes root")
            if not path.is_file() or path.is_symlink():
                raise DependencyLockError(
                    f"locked dependency artifact is absent: {package.artifact}")
            if _sha256(path) != package.sha256:
                raise DependencyLockError(
                    f"dependency digest mismatch: {package.artifact}")
        missing = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*.whl")
            if path.is_file()
        } - seen_files
        if missing:
            raise DependencyLockError(
                f"wheel files are not dependency-locked: {sorted(missing)}")


def load_dependency_lock(path: str | Path) -> DependencyLock:
    source = Path(path).resolve()
    try:
        raw = tomllib.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise DependencyLockError(
            f"could not parse dependency lock {source}: {exc}") from exc
    if not isinstance(raw, dict):
        raise DependencyLockError("dependency lock root must be a table")
    unknown = set(raw) - {"lock_version", "packages"}
    if unknown:
        raise DependencyLockError(
            f"dependency lock contains unknown keys: {sorted(unknown)}")
    version = raw.get("lock_version")
    if version != LOCK_VERSION:
        raise DependencyLockError(
            f"lock_version must be {LOCK_VERSION}")
    packages_raw = raw.get("packages", [])
    if not isinstance(packages_raw, list):
        raise DependencyLockError("packages must be an array of tables")
    packages = tuple(
        _package(item, index) for index, item in enumerate(packages_raw))
    lock = DependencyLock(version, packages, source)
    lock.verify(source.parent)
    return lock


def _package(raw, index: int) -> LockedPackage:
    where = f"packages[{index}]"
    if not isinstance(raw, dict):
        raise DependencyLockError(f"{where} must be a table")
    unknown = set(raw) - {
        "name", "version", "artifact", "sha256", "dependencies"}
    if unknown:
        raise DependencyLockError(
            f"{where} contains unknown keys: {sorted(unknown)}")
    name = raw.get("name")
    version = raw.get("version")
    artifact = raw.get("artifact")
    sha256 = raw.get("sha256")
    dependencies = raw.get("dependencies", [])
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise DependencyLockError(f"{where}.name is invalid")
    if not isinstance(version, str) or not version:
        raise DependencyLockError(f"{where}.version must be non-empty text")
    if (not isinstance(artifact, str) or not artifact
            or "\\" in artifact or artifact.startswith("/")
            or any(part in {"", ".", ".."} for part in artifact.split("/"))):
        raise DependencyLockError(
            f"{where}.artifact must be a relative POSIX path")
    if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
        raise DependencyLockError(f"{where}.sha256 must be lowercase SHA-256")
    if not isinstance(dependencies, list) or any(
            not isinstance(item, str) or not _NAME.fullmatch(item)
            for item in dependencies):
        raise DependencyLockError(
            f"{where}.dependencies must be package names")
    return LockedPackage(
        name, version, artifact, sha256, tuple(dependencies))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

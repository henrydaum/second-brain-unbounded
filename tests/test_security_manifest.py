from pathlib import Path
import hashlib

import pytest

from plugins.manifest_discovery import discover_artifacts
from plugins.plugin_discovery import _load_external
from security.artifacts import ArtifactError, build_artifact
from security.manifest import ManifestError, load_manifest


MANIFEST = """
schema_version = 1
id = "example.reader"
version = "1.0.0"
runtime = "python"
description = "Example"

[[handlers]]
kind = "tool"
name = "read_notes"
entrypoint = "plugin:run"
description = "Read notes"
persistent = false

[handlers.schema]
type = "object"

[[capabilities]]
right = "files.read"
resource = "notes/*"
labels = ["user-private"]

[budgets]
memory_mb = 128
cpu_seconds = 5
wall_seconds = 10
max_output_bytes = 4096
max_concurrency = 1
"""


def _package(tmp_path: Path) -> Path:
    root = tmp_path / "reader"
    root.mkdir()
    (root / "plugin.toml").write_text(MANIFEST, encoding="utf-8")
    (root / "plugin.lock").write_text(
        "lock_version = 1\n", encoding="utf-8")
    (root / "plugin.py").write_text(
        "raise RuntimeError('discovery executed hostile code')\n",
        encoding="utf-8")
    return root


def test_manifest_discovery_never_executes_plugin_code(tmp_path):
    root = _package(tmp_path)
    artifacts, errors = discover_artifacts([tmp_path])
    assert errors == ()
    assert [item.identity.plugin_id for item in artifacts] == ["example.reader"]
    assert artifacts[0].manifest.handlers[0].entrypoint == "plugin:run"


def test_legacy_external_discovery_fails_closed_without_oracle_switch(
        tmp_path, monkeypatch):
    sentinel = tmp_path / "executed"
    source = tmp_path / "hostile.py"
    source.write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).touch()\n",
        encoding="utf-8")
    monkeypatch.delenv("SECOND_BRAIN_ENABLE_LEGACY_PLUGIN_ORACLE", raising=False)
    assert _load_external("external.hostile", source, reload=True) is None
    assert not sentinel.exists()


def test_artifact_digest_binds_complete_closure(tmp_path):
    root = _package(tmp_path)
    helper = root / "helper.py"
    helper.write_text("VALUE = 1\n", encoding="utf-8")
    first = build_artifact(root)
    helper.write_text("VALUE = 2\n", encoding="utf-8")
    second = build_artifact(root)
    assert first.identity.digest != second.identity.digest
    assert first.verify() is False
    assert second.verify() is True


def test_manifest_rejects_unknown_fields(tmp_path):
    root = _package(tmp_path)
    path = root / "plugin.toml"
    path.write_text(MANIFEST + "\nmagic_authority = true\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="unknown keys"):
        load_manifest(path)


def test_artifact_refuses_symlinks_when_platform_can_create_them(tmp_path):
    root = _package(tmp_path)
    target = tmp_path / "outside.txt"
    target.write_text("secret", encoding="utf-8")
    link = root / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(ArtifactError, match="symlink"):
        build_artifact(root)


def test_artifact_identity_covers_bytecode_and_cache_directories(tmp_path):
    root = _package(tmp_path)
    cache = root / "__pycache__"
    cache.mkdir()
    bytecode = cache / "plugin.cpython-test.pyc"
    bytecode.write_bytes(b"first executable bytes")
    first = build_artifact(root)
    bytecode.write_bytes(b"changed executable bytes")
    second = build_artifact(root)
    assert first.identity.digest != second.identity.digest


def test_artifact_requires_and_verifies_dependency_lock(tmp_path):
    root = _package(tmp_path)
    (root / "plugin.lock").unlink()
    with pytest.raises(ArtifactError, match="dependency lock"):
        build_artifact(root)

    wheel = root / "dependencies" / "dep-1-py3-none-any.whl"
    wheel.parent.mkdir()
    wheel.write_bytes(b"wheel bytes")
    (root / "plugin.lock").write_text(
        "lock_version = 1\n", encoding="utf-8")
    with pytest.raises(ArtifactError, match="not dependency-locked"):
        build_artifact(root)

    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    (root / "plugin.lock").write_text(f"""
lock_version = 1

[[packages]]
name = "dep"
version = "1"
artifact = "dependencies/dep-1-py3-none-any.whl"
sha256 = "{digest}"
dependencies = []
""", encoding="utf-8")
    assert build_artifact(root).dependency_lock.packages[0].name == "dep"
    wheel.write_bytes(b"tampered")
    with pytest.raises(ArtifactError, match="digest mismatch"):
        build_artifact(root)

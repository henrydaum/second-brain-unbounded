import pytest

from security.artifacts import build_artifact
from security.capabilities import (
    AuthorityContext,
    ProvenanceChain,
    ResourceRegistry,
)
from security.delegation import DelegatedResource, DelegationService


def _artifact(tmp_path):
    root = tmp_path / "child"
    root.mkdir()
    (root / "plugin.toml").write_text("""
schema_version = 1
id = "example.child"
version = "1"
runtime = "python"

[[handlers]]
kind = "tool"
name = "child"
entrypoint = "plugin:run"

[[capabilities]]
right = "files.read"
resource = "notes/*"
""", encoding="utf-8")
    (root / "plugin.lock").write_text(
        "lock_version = 1\n", encoding="utf-8")
    (root / "plugin.py").write_text("pass\n", encoding="utf-8")
    return build_artifact(root)


def test_delegation_only_attenuates_and_preserves_identity(tmp_path):
    artifact = _artifact(tmp_path)
    resources = ResourceRegistry()
    parent_digest = "a" * 64
    parent = AuthorityContext(
        artifact_digest=parent_digest,
        principal="agent",
        provenance=ProvenanceChain("agent").enter(
            parent_digest, "tool:parent"),
        user_id=7,
        session_key="s",
        conversation_id=9,
    )
    source = resources.issue(
        artifact_digest=parent_digest,
        principal="agent",
        rights={"files.read", "files.write"},
        selector="notes/*",
        user_id=7,
        session_key="s",
        conversation_id=9,
        delegation_depth=1,
        binding=object(),
    )

    child = DelegationService(resources).delegate(
        parent=parent,
        child_artifact=artifact,
        child_handler=artifact.manifest.handlers[0],
        requested=[DelegatedResource(
            source.token, frozenset({"files.read"}), "notes/project")],
        unattended=True,
    )

    assert child.authority.principal == "agent"
    assert child.authority.user_id == 7
    assert child.authority.unattended
    assert child.resources[0].rights == frozenset({"files.read"})
    assert child.resources[0].selector == "notes/project"
    assert child.resources[0].delegation_depth == 0


def test_delegation_rejects_stolen_or_undeclared_authority(tmp_path):
    artifact = _artifact(tmp_path)
    resources = ResourceRegistry()
    parent_digest = "a" * 64
    parent = AuthorityContext(
        artifact_digest=parent_digest,
        principal="agent",
        provenance=ProvenanceChain("agent").enter(
            parent_digest, "tool:parent"),
    )
    stolen = resources.issue(
        artifact_digest="b" * 64,
        principal="agent",
        rights={"files.read"},
        selector="notes/*",
        delegation_depth=1,
    )
    service = DelegationService(resources)
    with pytest.raises(PermissionError, match="parent artifact"):
        service.delegate(
            parent=parent,
            child_artifact=artifact,
            child_handler=artifact.manifest.handlers[0],
            requested=[DelegatedResource(
                stolen.token, frozenset({"files.read"}))],
        )

    source = resources.issue(
        artifact_digest=parent_digest,
        principal="agent",
        rights={"files.write"},
        selector="notes/*",
        delegation_depth=1,
    )
    with pytest.raises(PermissionError, match="does not declare"):
        service.delegate(
            parent=parent,
            child_artifact=artifact,
            child_handler=artifact.manifest.handlers[0],
            requested=[DelegatedResource(
                source.token, frozenset({"files.write"}))],
        )

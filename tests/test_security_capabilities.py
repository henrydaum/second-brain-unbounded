import time
from pathlib import Path

import pytest

from security.capabilities import (
    AuthorityContext,
    CapabilityRequest,
    DataLabel,
    GrantLease,
    LeaseStore,
    MediationFacts,
    PolicyEngine,
    ProvenanceChain,
    ResourceRegistry,
)
from security.manifest import load_manifest
from security.vocabulary import EffectKind


def _manifest(tmp_path: Path, capabilities: str):
    path = tmp_path / "plugin.toml"
    path.write_text(
        f"""
schema_version = 1
id = "example.secure"
version = "1"
runtime = "python"

[[handlers]]
kind = "tool"
name = "secure"
entrypoint = "plugin:run"

{capabilities}
""",
        encoding="utf-8",
    )
    return load_manifest(path)


def _authority(digest="a" * 64, *, unattended=False, taint=None):
    provenance = ProvenanceChain("agent").enter(digest, "tool:secure")
    return AuthorityContext(
        artifact_digest=digest,
        principal="agent",
        provenance=provenance,
        user_id=7,
        session_key="s",
        conversation_id=11,
        unattended=unattended,
        taint=frozenset(taint or {DataLabel.PUBLIC}),
    )


def test_public_read_needs_resource_but_not_lease(tmp_path):
    manifest = _manifest(tmp_path, """
[[capabilities]]
right = "files.read"
resource = "notes/*"
""")
    resources, leases = ResourceRegistry(), LeaseStore()
    ref = resources.issue(
        artifact_digest="a" * 64, principal="agent",
        rights={"files.read"}, selector="notes/*", user_id=7,
        session_key="s", conversation_id=11)
    decision = PolicyEngine(resources, leases).decide(
        manifest, _authority(),
        CapabilityRequest("files.read", ref.token, "notes/a.md"))
    assert decision.allowed
    assert not decision.lease_id


def test_declaration_is_not_resource_authority(tmp_path):
    manifest = _manifest(tmp_path, """
[[capabilities]]
right = "files.read"
resource = "notes/*"
""")
    decision = PolicyEngine(ResourceRegistry(), LeaseStore()).decide(
        manifest, _authority(),
        CapabilityRequest("files.read", "", "notes/a.md"))
    assert not decision.allowed
    assert "resource" in decision.reason


def test_sensitive_read_requires_digest_bound_lease(tmp_path):
    manifest = _manifest(tmp_path, """
[[capabilities]]
right = "files.read"
resource = "notes/*"
labels = ["user-private"]
""")
    resources, leases = ResourceRegistry(), LeaseStore()
    ref = resources.issue(
        artifact_digest="a" * 64, principal="agent",
        rights={"files.read"}, selector="notes/*",
        labels={DataLabel.USER_PRIVATE}, user_id=7, session_key="s",
        conversation_id=11)
    request = CapabilityRequest("files.read", ref.token, "notes/a.md")
    policy = PolicyEngine(resources, leases)
    assert not policy.decide(manifest, _authority(), request).allowed

    wrong = GrantLease.create(
        artifact_digest="b" * 64, principal="agent", right="files.read",
        resource_selector="notes/*",
        allowed_labels=frozenset({DataLabel.PUBLIC, DataLabel.USER_PRIVATE}),
        user_id=7, session_key="s", conversation_id=11,
        remaining_uses=None)
    leases.add(wrong)
    assert not policy.decide(manifest, _authority(), request).allowed

    right = GrantLease.create(
        artifact_digest="a" * 64, principal="agent", right="files.read",
        resource_selector="notes/*",
        allowed_labels=frozenset({DataLabel.PUBLIC, DataLabel.USER_PRIVATE}),
        user_id=7, session_key="s", conversation_id=11,
        provenance_digests=("a" * 64,), remaining_uses=1)
    leases.add(right)
    decision = policy.decide(manifest, _authority(), request)
    assert decision.allowed and decision.lease_id == right.lease_id
    assert not policy.decide(manifest, _authority(), request).allowed


def test_reversible_write_is_kernel_fact_not_plugin_claim(tmp_path):
    manifest = _manifest(tmp_path, """
[[capabilities]]
right = "files.write"
resource = "notes/*"
""")
    resources, leases = ResourceRegistry(), LeaseStore()
    ref = resources.issue(
        artifact_digest="a" * 64, principal="agent",
        rights={"files.write"}, selector="notes/*", user_id=7,
        session_key="s", conversation_id=11)
    request = CapabilityRequest("files.write", ref.token, "notes/a.md")
    policy = PolicyEngine(resources, leases)
    assert not policy.decide(manifest, _authority(), request).allowed
    assert policy.decide(
        manifest, _authority(), request,
        MediationFacts(undo_ready=True)).allowed


def test_delegation_can_only_attenuate():
    resources = ResourceRegistry()
    parent = resources.issue(
        artifact_digest="a" * 64, principal="agent",
        rights={"files.read", "files.write"}, selector="notes/*",
        delegation_depth=1, expires_at=time.time() + 100)
    child = resources.attenuate(
        parent.token, artifact_digest="b" * 64,
        rights={"files.read"}, selector="notes/project/*",
        expires_at=time.time() + 1000)
    assert child.rights == {"files.read"}
    assert child.selector == "notes/project/*"
    assert child.expires_at <= parent.expires_at
    assert child.delegation_depth == 0
    with pytest.raises(PermissionError):
        resources.attenuate(
            parent.token, artifact_digest="b" * 64,
            rights={"network.http"}, selector="*")


def test_unattended_use_needs_explicit_lease_permission(tmp_path):
    manifest = _manifest(tmp_path, """
[[capabilities]]
right = "runtime.spawn_agent"
resource = "child"
""")
    resources, leases = ResourceRegistry(), LeaseStore()
    ref = resources.issue(
        artifact_digest="a" * 64, principal="agent",
        rights={"runtime.spawn_agent"}, selector="child")
    request = CapabilityRequest("runtime.spawn_agent", ref.token, "child")
    lease = GrantLease.create(
        artifact_digest="a" * 64, principal="agent",
        right="runtime.spawn_agent", resource_selector="child",
        allowed_labels=frozenset({DataLabel.PUBLIC}),
        remaining_uses=None, unattended=False)
    leases.add(lease)
    assert not PolicyEngine(resources, leases).decide(
        manifest, _authority(unattended=True), request).allowed


def test_egress_can_also_observe_and_taint_a_worker(tmp_path):
    manifest = _manifest(tmp_path, """
[[capabilities]]
right = "network.http"
resource = "https://api.example/*"
destinations = ["https://api.example/*"]
""")
    leases = LeaseStore()
    leases.add(GrantLease.create(
        artifact_digest="a" * 64,
        principal="agent",
        right="network.http",
        resource_selector="https://api.example/*",
        destination="https://api.example/*",
        allowed_labels=frozenset({
            DataLabel.PUBLIC, DataLabel.USER_PRIVATE}),
        user_id=7,
        session_key="s",
        conversation_id=11,
        remaining_uses=None,
    ))
    decision = PolicyEngine(ResourceRegistry(), leases).decide(
        manifest,
        _authority(),
        CapabilityRequest(
            "network.http",
            selector="https://api.example/data",
            destination="https://api.example/data",
        ),
        MediationFacts(
            destination_verified=True,
            observed_labels=frozenset({DataLabel.USER_PRIVATE}),
        ),
    )
    assert decision.allowed
    assert decision.effect == EffectKind.EGRESS
    assert decision.observes
    assert DataLabel.USER_PRIVATE in decision.labels

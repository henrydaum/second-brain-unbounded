import asyncio
from pathlib import Path

from security.broker import CapabilityBroker, PreparedEffect
from security.capabilities import (
    AuthorityContext,
    CapabilityRequest,
    DataLabel,
    LeaseStore,
    MediationFacts,
    PolicyEngine,
    ProvenanceChain,
)
from security.manifest import load_manifest
from security.capabilities import ResourceRegistry, GrantLease


def test_broker_can_install_and_immediately_consume_scoped_lease(tmp_path):
    path = tmp_path / "plugin.toml"
    path.write_text("""
schema_version = 1
id = "example.net"
version = "1"
runtime = "python"

[[handlers]]
kind = "tool"
name = "net"
entrypoint = "plugin:run"

[[capabilities]]
right = "network.http"
resource = "*"
destinations = ["https://api.example/*"]
""", encoding="utf-8")
    manifest = load_manifest(path)
    digest = "a" * 64
    authority = AuthorityContext(
        artifact_digest=digest, principal="agent",
        provenance=ProvenanceChain("agent").enter(digest, "tool:net"))
    leases = LeaseStore()
    asked = []

    def approve(_manifest, auth, request, decision):
        asked.append(request)
        return GrantLease.create(
            artifact_digest=digest, principal="agent",
            right=request.right, resource_selector=request.selector,
            destination=request.destination,
            allowed_labels=decision.labels,
            provenance_digests=(digest,), remaining_uses=1)

    broker = CapabilityBroker(
        PolicyEngine(ResourceRegistry(), leases),
        approval_provider=approve)
    broker.register(
        "network.http",
        lambda _auth, _payload: PreparedEffect(
            CapabilityRequest(
                "network.http",
                selector="https://api.example/v1",
                destination="https://api.example/v1"),
            MediationFacts(destination_verified=True),
            lambda: {"status": 200}))
    result = asyncio.run(broker.fulfill(
        invocation_id="i", manifest=manifest, authority=authority,
        right="network.http", payload={}))
    assert result == {"status": 200}
    assert len(asked) == 1
    assert next(iter(leases._leases.values())).remaining_uses == 0


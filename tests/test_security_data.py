import asyncio

import pytest

from pipeline.database import Database
from plugin_sdk import InvocationContext, ResourceHandle
from security.broker import CapabilityBroker, LocalCapabilityTransport
from security.capabilities import (
    AuthorityContext,
    DataLabel,
    GrantLease,
    LeaseStore,
    PolicyEngine,
    ProvenanceChain,
    ResourceRegistry,
)
from security.data import (
    DataCapabilityAdapter,
    PluginDataBinding,
    PluginDataStore,
    TypedViewRegistry,
)
from security.manifest import load_manifest


def _runtime(tmp_path, *, label=DataLabel.PUBLIC):
    path = tmp_path / "plugin.toml"
    path.write_text("""
schema_version = 1
id = "example.data"
version = "1"
runtime = "python"

[[handlers]]
kind = "tool"
name = "state"
entrypoint = "plugin:run"

[[capabilities]]
right = "data.read"
resource = "state"

[[capabilities]]
right = "data.write"
resource = "state"
""", encoding="utf-8")
    manifest = load_manifest(path)
    digest = "a" * 64
    db = Database(tmp_path / "db.sqlite")
    resources = ResourceRegistry()
    ref = resources.issue(
        artifact_digest=digest, principal="agent",
        rights={"data.read", "data.write"}, selector="state",
        binding=PluginDataBinding("main"),
        labels={label})
    leases = LeaseStore()
    if label != DataLabel.PUBLIC:
        for right in ("data.read", "data.write"):
            leases.add(GrantLease.create(
                artifact_digest=digest, principal="agent", right=right,
                resource_selector="state",
                allowed_labels=frozenset({DataLabel.PUBLIC, label}),
                remaining_uses=None))
    store = PluginDataStore(db)
    adapter = DataCapabilityAdapter(resources, store, TypedViewRegistry())
    broker = CapabilityBroker(PolicyEngine(resources, leases))
    broker.register("data.read", adapter.prepare_read)
    broker.register("data.write", adapter.prepare_write)
    authority = AuthorityContext(
        artifact_digest=digest, principal="agent",
        provenance=ProvenanceChain("agent").enter(digest, "tool:state"),
        taint=frozenset({label}))
    ctx = InvocationContext(
        LocalCapabilityTransport(
            broker, invocation_id="i", manifest=manifest,
            authority=authority),
        resources={"state": ResourceHandle(ref.token, "state")})
    return ctx, store


def test_plugin_state_is_namespaced_typed_and_reversible(tmp_path):
    ctx, store = _runtime(tmp_path)
    handle = ctx.resources["state"]
    written = asyncio.run(ctx.data.put(handle, "answer", {"value": 42}))
    row = asyncio.run(ctx.data.get(handle, "answer"))
    assert row["value"] == {"value": 42}
    assert row["version"] == 1
    assert store.rollback(written["transaction_id"])
    assert asyncio.run(ctx.data.get(handle, "answer")) is None


def test_optimistic_version_prevents_lost_update(tmp_path):
    ctx, _store = _runtime(tmp_path)
    handle = ctx.resources["state"]
    asyncio.run(ctx.data.put(handle, "k", 1))
    with pytest.raises(Exception, match="version conflict"):
        asyncio.run(ctx.data.put(handle, "k", 2, expected_version=0))


def test_sensitive_state_retains_labels(tmp_path):
    ctx, _store = _runtime(tmp_path, label=DataLabel.USER_PRIVATE)
    handle = ctx.resources["state"]
    asyncio.run(ctx.data.put(handle, "private", "value"))
    row = asyncio.run(ctx.data.get(handle, "private"))
    assert "user_private" in row["labels"]


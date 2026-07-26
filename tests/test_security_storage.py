from pipeline.database import Database
from security.capabilities import (
    AuthorityContext,
    CapabilityRequest,
    DataLabel,
    GrantLease,
    PolicyDecision,
    ProvenanceChain,
)
from security.storage import CapabilityAuditLog, SqliteLeaseStore
from security.vocabulary import EffectKind


def _authority():
    chain = ProvenanceChain("agent").enter("a" * 64, "tool:x")
    return AuthorityContext(
        artifact_digest="a" * 64, principal="agent", provenance=chain,
        user_id=7, session_key="s", conversation_id=9)


def test_sqlite_lease_consume_and_revocation_are_durable(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    store = SqliteLeaseStore(db)
    lease = GrantLease.create(
        artifact_digest="a" * 64, principal="agent",
        right="network.http", resource_selector="https://api.example/*",
        destination="https://api.example/*",
        allowed_labels=frozenset({DataLabel.PUBLIC}),
        user_id=7, session_key="s", conversation_id=9,
        provenance_digests=("a" * 64,), remaining_uses=2)
    store.add(lease)
    request = CapabilityRequest(
        "network.http", selector="https://api.example/v1",
        destination="https://api.example/v1")
    assert store.find_and_consume(
        authority=_authority(), request=request,
        labels=frozenset({DataLabel.PUBLIC})).lease_id == lease.lease_id

    reopened = SqliteLeaseStore(db)
    assert reopened.find_and_consume(
        authority=_authority(), request=request,
        labels=frozenset({DataLabel.PUBLIC})).lease_id == lease.lease_id
    assert reopened.find_and_consume(
        authority=_authority(), request=request,
        labels=frozenset({DataLabel.PUBLIC})) is None
    assert reopened.revoke(lease.lease_id)


def test_capability_audit_does_not_store_bearer_token(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    audit = CapabilityAuditLog(db)
    request = CapabilityRequest(
        "files.read", resource_token="very-secret-bearer-token",
        selector="notes/a")
    audit.record(
        _authority(), request,
        PolicyDecision(
            True, "ok", EffectKind.OBSERVE,
            labels=frozenset({DataLabel.PUBLIC})))
    row = db.conn.execute(
        "SELECT * FROM capability_decisions").fetchone()
    assert row["resource_token_hint"] == "very-sec"
    assert "very-secret-bearer-token" not in str(dict(row))


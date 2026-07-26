"""Durable scoped leases and reference-monitor decisions."""

from __future__ import annotations

import json
import time
from contextlib import nullcontext

from security.capabilities import (
    AuthorityContext,
    CapabilityRequest,
    DataLabel,
    GrantLease,
    PolicyDecision,
)
from security.manifest import _selector_contains


class SqliteLeaseStore:
    """Lease store backed by the kernel database.

    Matching and usage-count decrement happen under the database lock in one
    transaction, so two concurrent workers cannot both consume a one-use grant.
    """

    def __init__(self, db):
        self.db = db
        self._setup()

    def _guard(self):
        lock = getattr(self.db, "lock", None)
        return lock if lock is not None else nullcontext()

    def _setup(self) -> None:
        with self._guard():
            self.db.conn.execute("""
                CREATE TABLE IF NOT EXISTS capability_leases (
                    lease_id TEXT PRIMARY KEY,
                    artifact_digest TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    right_name TEXT NOT NULL,
                    resource_selector TEXT NOT NULL,
                    allowed_labels_json TEXT NOT NULL,
                    destination TEXT NOT NULL DEFAULT '',
                    user_id INTEGER,
                    session_key TEXT,
                    conversation_id INTEGER,
                    unattended INTEGER NOT NULL DEFAULT 0,
                    expires_at REAL,
                    remaining_uses INTEGER,
                    provenance_json TEXT NOT NULL DEFAULT '[]',
                    revoked INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL
                )
            """)
            self.db.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_capability_lease_lookup
                ON capability_leases(
                    artifact_digest, principal, right_name, revoked, expires_at)
            """)
            self.db.conn.commit()

    def add(self, lease: GrantLease) -> None:
        with self._guard():
            self.db.conn.execute("""
                INSERT INTO capability_leases (
                    lease_id, artifact_digest, principal, right_name,
                    resource_selector, allowed_labels_json, destination,
                    user_id, session_key, conversation_id, unattended,
                    expires_at, remaining_uses, provenance_json, revoked,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                lease.lease_id, lease.artifact_digest, lease.principal,
                lease.right, lease.resource_selector,
                json.dumps(sorted(int(item) for item in lease.allowed_labels)),
                lease.destination, lease.user_id, lease.session_key,
                lease.conversation_id, int(lease.unattended), lease.expires_at,
                lease.remaining_uses, json.dumps(lease.provenance_digests),
                int(lease.revoked), time.time(),
            ))
            self.db.conn.commit()

    def revoke(self, lease_id: str) -> bool:
        with self._guard():
            cur = self.db.conn.execute(
                "UPDATE capability_leases SET revoked = 1 "
                "WHERE lease_id = ? AND revoked = 0",
                (lease_id,))
            self.db.conn.commit()
            return cur.rowcount > 0

    def find_and_consume(self, *, authority: AuthorityContext,
                         request: CapabilityRequest,
                         labels: frozenset[DataLabel]) -> GrantLease | None:
        now = time.time()
        provenance = tuple(
            item.artifact_digest for item in authority.provenance.frames)
        with self._guard():
            rows = self.db.conn.execute("""
                SELECT * FROM capability_leases
                WHERE artifact_digest = ?
                  AND principal = ?
                  AND right_name = ?
                  AND revoked = 0
                  AND (expires_at IS NULL OR expires_at > ?)
                  AND (remaining_uses IS NULL OR remaining_uses > 0)
                ORDER BY created_at, lease_id
            """, (
                authority.artifact_digest, authority.principal,
                request.right, now,
            )).fetchall()
            for row in rows:
                lease = _lease_from_row(row)
                if not _selector_contains(
                        lease.resource_selector, request.selector):
                    continue
                if request.destination and not _selector_contains(
                        lease.destination, request.destination):
                    continue
                if not labels.issubset(lease.allowed_labels):
                    continue
                if lease.user_id is not None and lease.user_id != authority.user_id:
                    continue
                if (lease.session_key is not None
                        and lease.session_key != authority.session_key):
                    continue
                if (lease.conversation_id is not None
                        and lease.conversation_id != authority.conversation_id):
                    continue
                if authority.unattended and not lease.unattended:
                    continue
                if lease.provenance_digests and (
                        lease.provenance_digests != provenance):
                    continue
                if lease.remaining_uses is not None:
                    cur = self.db.conn.execute("""
                        UPDATE capability_leases
                        SET remaining_uses = remaining_uses - 1
                        WHERE lease_id = ?
                          AND revoked = 0
                          AND remaining_uses > 0
                    """, (lease.lease_id,))
                    if cur.rowcount != 1:
                        self.db.conn.rollback()
                        continue
                    lease.remaining_uses -= 1
                self.db.conn.commit()
                return lease
            self.db.conn.commit()
        return None


class CapabilityAuditLog:
    def __init__(self, db):
        self.db = db
        self._setup()

    def _guard(self):
        lock = getattr(self.db, "lock", None)
        return lock if lock is not None else nullcontext()

    def _setup(self) -> None:
        with self._guard():
            self.db.conn.execute("""
                CREATE TABLE IF NOT EXISTS capability_decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    artifact_digest TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    provenance_json TEXT NOT NULL,
                    user_id INTEGER,
                    session_key TEXT,
                    conversation_id INTEGER,
                    right_name TEXT NOT NULL,
                    resource_token_hint TEXT,
                    selector TEXT,
                    destination TEXT,
                    labels_json TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    effect_kind TEXT,
                    lease_id TEXT
                )
            """)
            self.db.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_capability_decisions_artifact
                ON capability_decisions(artifact_digest, id)
            """)
            self.db.conn.commit()

    def record(self, authority: AuthorityContext, request: CapabilityRequest,
               decision: PolicyDecision) -> None:
        # Opaque resource tokens are still sensitive bearer material.  The log
        # stores only a short non-usable hint for correlation.
        hint = request.resource_token[:8] if request.resource_token else ""
        provenance = [
            {"artifact_digest": item.artifact_digest, "handler": item.handler}
            for item in authority.provenance.frames
        ]
        with self._guard():
            self.db.conn.execute("""
                INSERT INTO capability_decisions (
                    ts, artifact_digest, principal, provenance_json, user_id,
                    session_key, conversation_id, right_name,
                    resource_token_hint, selector, destination, labels_json,
                    allowed, reason, effect_kind, lease_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                time.time(), authority.artifact_digest, authority.principal,
                json.dumps(provenance, sort_keys=True), authority.user_id,
                authority.session_key, authority.conversation_id, request.right,
                hint, request.selector, request.destination,
                json.dumps(sorted(int(item) for item in decision.labels)),
                int(decision.allowed), decision.reason,
                decision.effect.value if decision.effect else None,
                decision.lease_id or None,
            ))
            self.db.conn.commit()


def _lease_from_row(row) -> GrantLease:
    return GrantLease(
        lease_id=row["lease_id"],
        artifact_digest=row["artifact_digest"],
        principal=row["principal"],
        right=row["right_name"],
        resource_selector=row["resource_selector"],
        allowed_labels=frozenset(
            DataLabel(item)
            for item in json.loads(row["allowed_labels_json"])),
        destination=row["destination"] or "",
        user_id=row["user_id"],
        session_key=row["session_key"],
        conversation_id=row["conversation_id"],
        unattended=bool(row["unattended"]),
        expires_at=row["expires_at"],
        remaining_uses=row["remaining_uses"],
        provenance_digests=tuple(json.loads(row["provenance_json"])),
        revoked=bool(row["revoked"]),
    )


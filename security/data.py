"""Namespaced plugin data and kernel-owned typed views; no plugin SQL."""

from __future__ import annotations

import json
import secrets
import time
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from security.broker import PreparedEffect
from security.capabilities import (
    AuthorityContext,
    CapabilityRequest,
    DataLabel,
    MediationFacts,
    ResourceRegistry,
)


class DataStoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class PluginDataBinding:
    namespace: str
    allowed_views: frozenset[str] = frozenset()


@dataclass(frozen=True)
class StoredValue:
    key: str
    value: Any
    version: int
    labels: frozenset[DataLabel]
    updated_at: float


class PluginDataStore:
    def __init__(self, db):
        self.db = db
        self._setup()

    def _guard(self):
        return getattr(self.db, "lock", None) or nullcontext()

    def _setup(self):
        with self._guard():
            self.db.conn.execute("""
                CREATE TABLE IF NOT EXISTS plugin_kv (
                    artifact_digest TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    key_name TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    labels_json TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (artifact_digest, namespace, key_name)
                )
            """)
            self.db.conn.execute("""
                CREATE TABLE IF NOT EXISTS plugin_kv_journal (
                    transaction_id TEXT PRIMARY KEY,
                    ts REAL NOT NULL,
                    artifact_digest TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    key_name TEXT NOT NULL,
                    prior_exists INTEGER NOT NULL,
                    prior_value_json TEXT,
                    prior_labels_json TEXT,
                    prior_version INTEGER,
                    prior_updated_at REAL,
                    rolled_back INTEGER NOT NULL DEFAULT 0
                )
            """)
            self.db.conn.commit()

    def metadata(self, digest: str, namespace: str,
                 key: str) -> tuple[int, frozenset[DataLabel]] | None:
        with self._guard():
            row = self.db.conn.execute("""
                SELECT version, labels_json FROM plugin_kv
                WHERE artifact_digest = ? AND namespace = ? AND key_name = ?
            """, (digest, namespace, key)).fetchone()
        if row is None:
            return None
        return int(row["version"]), _labels(row["labels_json"])

    def get(self, digest: str, namespace: str, key: str) -> StoredValue | None:
        with self._guard():
            row = self.db.conn.execute("""
                SELECT * FROM plugin_kv
                WHERE artifact_digest = ? AND namespace = ? AND key_name = ?
            """, (digest, namespace, key)).fetchone()
        return _stored(row) if row is not None else None

    def list(self, digest: str, namespace: str, prefix: str = "",
             limit: int = 100) -> list[StoredValue]:
        limit = max(1, min(int(limit), 1000))
        with self._guard():
            rows = self.db.conn.execute("""
                SELECT * FROM plugin_kv
                WHERE artifact_digest = ? AND namespace = ?
                  AND key_name LIKE ? ESCAPE '\\'
                ORDER BY key_name
                LIMIT ?
            """, (
                digest, namespace, _like_escape(prefix) + "%", limit,
            )).fetchall()
        return [_stored(row) for row in rows]

    def put(self, digest: str, namespace: str, key: str, value: Any,
            labels: frozenset[DataLabel], *,
            expected_version: int | None = None) -> dict:
        encoded = _json(value)
        labels_json = json.dumps(sorted(int(item) for item in labels))
        transaction_id = secrets.token_urlsafe(24)
        now = time.time()
        with self._guard():
            try:
                self.db.conn.execute("BEGIN IMMEDIATE")
                row = self.db.conn.execute("""
                    SELECT * FROM plugin_kv
                    WHERE artifact_digest = ? AND namespace = ? AND key_name = ?
                """, (digest, namespace, key)).fetchone()
                current = int(row["version"]) if row is not None else 0
                if expected_version is not None and expected_version != current:
                    raise DataStoreError(
                        f"version conflict: expected {expected_version}, got {current}")
                self._record_inverse(
                    transaction_id, now, digest, namespace, key, row)
                version = current + 1
                self.db.conn.execute("""
                    INSERT INTO plugin_kv (
                        artifact_digest, namespace, key_name, value_json,
                        labels_json, version, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(artifact_digest, namespace, key_name)
                    DO UPDATE SET value_json = excluded.value_json,
                                  labels_json = excluded.labels_json,
                                  version = excluded.version,
                                  updated_at = excluded.updated_at
                """, (
                    digest, namespace, key, encoded, labels_json, version, now,
                ))
                self.db.conn.commit()
            except Exception:
                self.db.conn.rollback()
                raise
        return {"transaction_id": transaction_id, "version": version}

    def delete(self, digest: str, namespace: str, key: str,
               *, expected_version: int | None = None) -> dict:
        transaction_id = secrets.token_urlsafe(24)
        now = time.time()
        with self._guard():
            try:
                self.db.conn.execute("BEGIN IMMEDIATE")
                row = self.db.conn.execute("""
                    SELECT * FROM plugin_kv
                    WHERE artifact_digest = ? AND namespace = ? AND key_name = ?
                """, (digest, namespace, key)).fetchone()
                current = int(row["version"]) if row is not None else 0
                if expected_version is not None and expected_version != current:
                    raise DataStoreError(
                        f"version conflict: expected {expected_version}, got {current}")
                self._record_inverse(
                    transaction_id, now, digest, namespace, key, row)
                self.db.conn.execute("""
                    DELETE FROM plugin_kv
                    WHERE artifact_digest = ? AND namespace = ? AND key_name = ?
                """, (digest, namespace, key))
                self.db.conn.commit()
            except Exception:
                self.db.conn.rollback()
                raise
        return {"transaction_id": transaction_id, "existed": row is not None}

    def rollback(self, transaction_id: str) -> bool:
        with self._guard():
            try:
                self.db.conn.execute("BEGIN IMMEDIATE")
                row = self.db.conn.execute("""
                    SELECT * FROM plugin_kv_journal
                    WHERE transaction_id = ? AND rolled_back = 0
                """, (transaction_id,)).fetchone()
                if row is None:
                    self.db.conn.rollback()
                    return False
                key = (
                    row["artifact_digest"], row["namespace"], row["key_name"])
                if row["prior_exists"]:
                    self.db.conn.execute("""
                        INSERT INTO plugin_kv (
                            artifact_digest, namespace, key_name, value_json,
                            labels_json, version, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(artifact_digest, namespace, key_name)
                        DO UPDATE SET value_json = excluded.value_json,
                                      labels_json = excluded.labels_json,
                                      version = excluded.version,
                                      updated_at = excluded.updated_at
                    """, (*key, row["prior_value_json"],
                          row["prior_labels_json"], row["prior_version"],
                          row["prior_updated_at"]))
                else:
                    self.db.conn.execute("""
                        DELETE FROM plugin_kv
                        WHERE artifact_digest = ? AND namespace = ? AND key_name = ?
                    """, key)
                self.db.conn.execute("""
                    UPDATE plugin_kv_journal SET rolled_back = 1
                    WHERE transaction_id = ?
                """, (transaction_id,))
                self.db.conn.commit()
                return True
            except Exception:
                self.db.conn.rollback()
                raise

    def _record_inverse(self, transaction_id, now, digest, namespace, key,
                        row) -> None:
        self.db.conn.execute("""
            INSERT INTO plugin_kv_journal (
                transaction_id, ts, artifact_digest, namespace, key_name,
                prior_exists, prior_value_json, prior_labels_json,
                prior_version, prior_updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            transaction_id, now, digest, namespace, key, int(row is not None),
            row["value_json"] if row is not None else None,
            row["labels_json"] if row is not None else None,
            row["version"] if row is not None else None,
            row["updated_at"] if row is not None else None,
        ))


class TypedViewRegistry:
    """Kernel-owned named views.  Plugins never provide SQL or callables."""

    def __init__(self):
        self._views: dict[
            str, tuple[Callable[[AuthorityContext, Mapping[str, Any]], Any],
                       frozenset[DataLabel]]] = {}

    def register(self, name: str, reader, *,
                 labels=(DataLabel.USER_PRIVATE,)) -> None:
        if name in self._views:
            raise ValueError(f"view already registered: {name}")
        self._views[name] = (reader, frozenset(labels))

    def labels(self, name: str) -> frozenset[DataLabel]:
        try:
            return self._views[name][1]
        except KeyError as exc:
            raise DataStoreError(f"unknown data view {name!r}") from exc

    def read(self, name: str, authority: AuthorityContext,
             params: Mapping[str, Any]) -> Any:
        try:
            reader = self._views[name][0]
        except KeyError as exc:
            raise DataStoreError(f"unknown data view {name!r}") from exc
        return reader(authority, dict(params))


class DataCapabilityAdapter:
    def __init__(self, resources: ResourceRegistry, store: PluginDataStore,
                 views: TypedViewRegistry):
        self.resources = resources
        self.store = store
        self.views = views

    def prepare_read(self, authority: AuthorityContext,
                     payload: Mapping[str, Any]) -> PreparedEffect:
        request, binding = self._request(authority, "data.read", payload)
        operation = payload.get("operation")
        if operation == "get":
            key = _key(payload.get("key"))
            meta = self.store.metadata(
                authority.artifact_digest, binding.namespace, key)
            labels = meta[1] if meta else frozenset({DataLabel.PUBLIC})
            request = _with_labels(request, labels)
            return PreparedEffect(
                request, MediationFacts(),
                lambda: _wire_stored(self.store.get(
                    authority.artifact_digest, binding.namespace, key)))
        if operation == "list":
            prefix = _prefix(payload.get("prefix", ""))
            limit = max(1, min(int(payload.get("limit", 100)), 1000))
            rows = self.store.list(
                authority.artifact_digest, binding.namespace, prefix, limit)
            labels = frozenset(
                label for row in rows for label in row.labels) or frozenset(
                    {DataLabel.PUBLIC})
            request = _with_labels(request, labels)
            return PreparedEffect(
                request, MediationFacts(),
                lambda: [_wire_stored(row) for row in rows])
        if operation == "view":
            name = str(payload.get("view") or "")
            if name not in binding.allowed_views:
                raise DataStoreError("view is not granted by this resource")
            params = payload.get("params") or {}
            if not isinstance(params, dict):
                raise DataStoreError("view params must be an object")
            request = _with_labels(request, self.views.labels(name))
            return PreparedEffect(
                request, MediationFacts(),
                lambda: self.views.read(name, authority, params))
        raise DataStoreError("data.read operation must be get, list, or view")

    def prepare_write(self, authority: AuthorityContext,
                      payload: Mapping[str, Any]) -> PreparedEffect:
        request, binding = self._request(authority, "data.write", payload)
        operation = payload.get("operation")
        key = _key(payload.get("key"))
        expected = payload.get("expected_version")
        if expected is not None and (
                isinstance(expected, bool) or not isinstance(expected, int)
                or expected < 0):
            raise DataStoreError("expected_version must be non-negative")
        if operation == "put":
            value = payload.get("value")
            _json(value)
            return PreparedEffect(
                request, MediationFacts(undo_ready=True),
                lambda: self.store.put(
                    authority.artifact_digest, binding.namespace, key, value,
                    authority.taint, expected_version=expected))
        if operation == "delete":
            return PreparedEffect(
                request, MediationFacts(undo_ready=True),
                lambda: self.store.delete(
                    authority.artifact_digest, binding.namespace, key,
                    expected_version=expected))
        raise DataStoreError("data.write operation must be put or delete")

    def _request(self, authority: AuthorityContext, right: str,
                 payload: Mapping[str, Any]):
        token = payload.get("resource")
        selector = payload.get("selector")
        if not isinstance(token, str) or not isinstance(selector, str):
            raise DataStoreError("resource and selector must be strings")
        binding = self.resources.binding(token)
        if not isinstance(binding, PluginDataBinding):
            raise DataStoreError("resource is not a plugin data binding")
        return CapabilityRequest(right, token, selector), binding


def _stored(row) -> StoredValue:
    return StoredValue(
        key=row["key_name"],
        value=json.loads(row["value_json"]),
        version=int(row["version"]),
        labels=_labels(row["labels_json"]),
        updated_at=float(row["updated_at"]),
    )


def _wire_stored(row: StoredValue | None):
    if row is None:
        return None
    return {
        "key": row.key, "value": row.value, "version": row.version,
        "labels": [item.name.lower() for item in sorted(row.labels)],
        "updated_at": row.updated_at,
    }


def _labels(raw: str) -> frozenset[DataLabel]:
    return frozenset(DataLabel(item) for item in json.loads(raw))


def _with_labels(request: CapabilityRequest,
                 labels: frozenset[DataLabel]) -> CapabilityRequest:
    return CapabilityRequest(
        right=request.right, resource_token=request.resource_token,
        selector=request.selector, destination=request.destination,
        payload_labels=labels)


def _json(value: Any) -> str:
    try:
        return json.dumps(
            value, allow_nan=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise DataStoreError("value must be strict JSON data") from exc


def _key(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise DataStoreError("key must be 1-512 characters")
    if "\x00" in value:
        raise DataStoreError("key may not contain NUL")
    return value


def _prefix(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 512 or "\x00" in value:
        raise DataStoreError("prefix must be at most 512 characters")
    return value


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


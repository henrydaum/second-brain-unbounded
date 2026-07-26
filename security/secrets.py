"""Opaque, destination-bound references to kernel-owned credentials."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass

from security.manifest import _selector_contains


@dataclass(frozen=True)
class SecretRef:
    token: str
    artifact_digest: str
    destination: str
    expires_at: float | None = None


class SecretRegistry:
    def __init__(self):
        self._items: dict[str, tuple[SecretRef, str]] = {}
        self._lock = threading.RLock()

    def issue(self, *, artifact_digest: str, destination: str,
              value: str, expires_at: float | None = None) -> SecretRef:
        if not artifact_digest or not destination or not value:
            raise ValueError(
                "artifact_digest, destination, and value are required")
        ref = SecretRef(
            token=secrets.token_urlsafe(32),
            artifact_digest=artifact_digest,
            destination=destination,
            expires_at=expires_at,
        )
        with self._lock:
            self._items[ref.token] = (ref, value)
        return ref

    def resolve(self, token: str, artifact_digest: str,
                destination: str) -> str:
        with self._lock:
            item = self._items.get(token)
            if item is None:
                raise PermissionError("secret reference is absent or revoked")
            ref, value = item
            if ref.expires_at is not None and time.time() >= ref.expires_at:
                self._items.pop(token, None)
                raise PermissionError("secret reference expired")
            if ref.artifact_digest != artifact_digest:
                raise PermissionError("secret belongs to a different artifact")
            if not _selector_contains(ref.destination, destination):
                raise PermissionError(
                    "secret is not valid for this destination")
            return value

    def revoke(self, token: str) -> bool:
        with self._lock:
            return self._items.pop(token, None) is not None


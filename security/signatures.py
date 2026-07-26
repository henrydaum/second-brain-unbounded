"""Detached Ed25519 store-origin signatures for plugin artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from security.artifacts import PluginArtifact

SIGNATURE_VERSION = 1
_DOMAIN = b"SECOND-BRAIN-STORE-SIGNATURE-V1\0"


class StoreSignatureError(PermissionError):
    pass


@dataclass(frozen=True)
class StoreSignature:
    key_id: str
    plugin_id: str
    artifact_digest: str
    signature: bytes
    source_path: Path


class StoreSignatureVerifier:
    """Verifier configured only with kernel/admin-owned public keys."""

    def __init__(self, trusted_keys: Mapping[str, bytes]):
        self._keys = {}
        for key_id, raw in trusted_keys.items():
            expected = key_identifier(raw)
            if key_id != expected:
                raise StoreSignatureError(
                    f"trusted key id mismatch: expected {expected}")
            try:
                self._keys[key_id] = Ed25519PublicKey.from_public_bytes(raw)
            except ValueError as exc:
                raise StoreSignatureError(
                    f"invalid Ed25519 public key {key_id}") from exc

    def verify(
        self,
        artifact: PluginArtifact,
        signature_path: str | Path,
    ) -> StoreSignature:
        record = load_store_signature(signature_path)
        if record.plugin_id != artifact.identity.plugin_id:
            raise StoreSignatureError(
                "signature names a different plugin id")
        if record.artifact_digest != artifact.identity.digest:
            raise StoreSignatureError(
                "signature names a different artifact digest")
        key = self._keys.get(record.key_id)
        if key is None:
            raise StoreSignatureError("signature key is not trusted")
        try:
            key.verify(record.signature, signature_message(artifact))
        except InvalidSignature as exc:
            raise StoreSignatureError("artifact signature is invalid") from exc
        return record


def load_store_signature(path: str | Path) -> StoreSignature:
    source = Path(path).resolve()
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StoreSignatureError(
            f"could not read store signature: {exc}") from exc
    if not isinstance(raw, dict):
        raise StoreSignatureError("store signature root must be an object")
    expected = {
        "version", "algorithm", "key_id", "plugin_id",
        "artifact_digest", "signature",
    }
    if set(raw) != expected:
        raise StoreSignatureError(
            f"invalid store signature fields: {sorted(set(raw) ^ expected)}")
    if raw["version"] != SIGNATURE_VERSION or raw["algorithm"] != "ed25519":
        raise StoreSignatureError("unsupported store signature format")
    for name in ("key_id", "plugin_id", "artifact_digest", "signature"):
        if not isinstance(raw[name], str):
            raise StoreSignatureError(f"{name} must be text")
    if (len(raw["artifact_digest"]) != 64
            or any(c not in "0123456789abcdef"
                   for c in raw["artifact_digest"])):
        raise StoreSignatureError("artifact_digest is not SHA-256 hex")
    try:
        signature = base64.b64decode(raw["signature"], validate=True)
    except ValueError as exc:
        raise StoreSignatureError("signature is not canonical base64") from exc
    if len(signature) != 64:
        raise StoreSignatureError("Ed25519 signature must be 64 bytes")
    return StoreSignature(
        key_id=raw["key_id"],
        plugin_id=raw["plugin_id"],
        artifact_digest=raw["artifact_digest"],
        signature=signature,
        source_path=source,
    )


def signature_message(artifact: PluginArtifact) -> bytes:
    return (
        _DOMAIN
        + artifact.identity.plugin_id.encode("utf-8")
        + b"\0"
        + bytes.fromhex(artifact.identity.digest)
    )


def key_identifier(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise StoreSignatureError("Ed25519 public keys must be 32 bytes")
    return hashlib.sha256(public_key).hexdigest()

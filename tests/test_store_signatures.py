import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security.activation import ArtifactStore
from security.artifacts import build_artifact
from security.signatures import (
    StoreSignatureError,
    StoreSignatureVerifier,
    key_identifier,
    signature_message,
)


def _artifact(tmp_path):
    root = tmp_path / "staged"
    root.mkdir()
    (root / "plugin.toml").write_text("""
schema_version = 1
id = "store.signed"
version = "1"
runtime = "python"

[[handlers]]
kind = "tool"
name = "signed"
entrypoint = "plugin:run"
""", encoding="utf-8")
    (root / "plugin.lock").write_text(
        "lock_version = 1\n", encoding="utf-8")
    (root / "plugin.py").write_text(
        "async def run(ctx, params): return params\n", encoding="utf-8")
    return root, build_artifact(root)


def _signed(tmp_path, artifact, private):
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    path = tmp_path / "artifact.sig"
    path.write_text(json.dumps({
        "version": 1,
        "algorithm": "ed25519",
        "key_id": key_identifier(public),
        "plugin_id": artifact.identity.plugin_id,
        "artifact_digest": artifact.identity.digest,
        "signature": base64.b64encode(
            private.sign(signature_message(artifact))).decode("ascii"),
    }), encoding="utf-8")
    return path, public


def test_store_import_requires_valid_trusted_origin_signature(tmp_path):
    root, artifact = _artifact(tmp_path)
    private = Ed25519PrivateKey.generate()
    signature, public = _signed(tmp_path, artifact, private)
    verifier = StoreSignatureVerifier({
        key_identifier(public): public,
    })
    installed = ArtifactStore(
        tmp_path / "artifacts").import_store_staged(
            root, signature_path=signature, verifier=verifier)
    assert installed.identity == artifact.identity


def test_store_signature_does_not_transfer_to_changed_bytes(tmp_path):
    root, artifact = _artifact(tmp_path)
    private = Ed25519PrivateKey.generate()
    signature, public = _signed(tmp_path, artifact, private)
    (root / "plugin.py").write_text(
        "async def run(ctx, params): return 'changed'\n", encoding="utf-8")
    verifier = StoreSignatureVerifier({
        key_identifier(public): public,
    })
    with pytest.raises(StoreSignatureError, match="different artifact"):
        ArtifactStore(tmp_path / "artifacts").import_store_staged(
            root, signature_path=signature, verifier=verifier)

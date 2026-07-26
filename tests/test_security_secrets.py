import pytest

from security.secrets import SecretRegistry


def test_secret_refs_bind_artifact_and_destination():
    registry = SecretRegistry()
    ref = registry.issue(
        artifact_digest="a" * 64,
        destination="https://api.example/*",
        value="secret")
    assert registry.resolve(
        ref.token, "a" * 64, "https://api.example/v1") == "secret"
    with pytest.raises(PermissionError):
        registry.resolve(ref.token, "b" * 64, "https://api.example/v1")
    with pytest.raises(PermissionError):
        registry.resolve(ref.token, "a" * 64, "https://evil.example/")


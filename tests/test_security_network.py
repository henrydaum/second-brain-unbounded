import socket

import pytest

from security.network import (
    NetworkCapabilityAdapter,
    NetworkPolicyError,
    resolve_pinned_address,
    validate_url,
)


def test_url_validation_refuses_non_http_and_credentials():
    with pytest.raises(NetworkPolicyError):
        validate_url("file:///etc/passwd")
    with pytest.raises(NetworkPolicyError):
        validate_url("https://user:pass@example.com/")


def test_dns_policy_refuses_loopback(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
         ("127.0.0.1", 443))
    ])
    with pytest.raises(NetworkPolicyError, match="forbidden"):
        resolve_pinned_address("evil.example", 443)
    assert resolve_pinned_address(
        "explicit-local.example", 443, allow_private=True) == "127.0.0.1"


def test_cross_origin_redirect_is_never_followed(monkeypatch):
    adapter = NetworkCapabilityAdapter()
    responses = iter([
        {"status": 302, "headers": {"location": "https://other.example/x"},
         "body": b"", "url": "https://example.com/"},
    ])
    monkeypatch.setattr(
        adapter, "_request_once", lambda *_a, **_k: next(responses))
    with pytest.raises(NetworkPolicyError, match="cross-origin"):
        adapter._perform(
            "GET", validate_url("https://example.com/"), {}, None, {}, 5,
            "a" * 64)


def test_secrets_are_resolved_only_at_enactment(monkeypatch):
    seen = []
    adapter = NetworkCapabilityAdapter(
        secret_resolver=lambda ref, digest, destination: (
            seen.append((ref, digest, destination)) or "secret-value"))
    monkeypatch.setattr(adapter, "_request_once", lambda method, url, headers, body, timeout: {
        "status": 200, "headers": {}, "body": b"ok", "url": url.url,
        "sent_headers": headers,
    })
    authority = type("Authority", (), {"artifact_digest": "a" * 64})()
    prepared = adapter.prepare_http(authority, {
        "method": "GET", "destination": "https://example.com/",
        "secret_refs": {"Authorization": "api-key-ref"},
    })
    assert seen == []
    response = prepared.enact()
    assert seen == [("api-key-ref", "a" * 64, "https://example.com/")]
    assert response["sent_headers"]["Authorization"] == "secret-value"

"""Broker-owned HTTP with destination and redirect revalidation."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.parse import urljoin, urlsplit, urlunsplit

from security.broker import PreparedEffect
from security.capabilities import (
    AuthorityContext,
    CapabilityRequest,
    DataLabel,
    MediationFacts,
)

_REDIRECTS = {301, 302, 303, 307, 308}
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})


class NetworkPolicyError(PermissionError):
    pass


@dataclass(frozen=True)
class ValidatedUrl:
    url: str
    scheme: str
    host: str
    port: int
    target: str

    @property
    def origin(self) -> tuple[str, str, int]:
        return self.scheme, self.host, self.port


class NetworkCapabilityAdapter:
    def __init__(self, *,
                 secret_resolver: Callable[[str, str, str], str] | None = None,
                 allow_private_hosts: frozenset[str] = frozenset(),
                 max_response_bytes: int = 8 * 1024 * 1024,
                 max_redirects: int = 5,
                 timeout_cap: float = 120.0):
        self.secret_resolver = secret_resolver
        self.allow_private_hosts = frozenset(
            item.lower().rstrip(".") for item in allow_private_hosts)
        self.max_response_bytes = int(max_response_bytes)
        self.max_redirects = int(max_redirects)
        self.timeout_cap = float(timeout_cap)

    def prepare_http(self, authority: AuthorityContext,
                     payload: Mapping[str, Any]) -> PreparedEffect:
        method = str(payload.get("method") or "GET").upper()
        if method not in _METHODS:
            raise NetworkPolicyError(f"unsupported HTTP method {method!r}")
        validated = validate_url(str(
            payload.get("destination") or payload.get("selector") or ""))
        headers = payload.get("headers") or {}
        if not isinstance(headers, dict) or any(
                not isinstance(k, str) or not isinstance(v, str)
                for k, v in headers.items()):
            raise NetworkPolicyError("headers must be string pairs")
        body = payload.get("body")
        if body is not None and not isinstance(body, (str, bytes, bytearray)):
            raise NetworkPolicyError("HTTP body must be text or bytes")
        raw_body = (
            body.encode("utf-8") if isinstance(body, str)
            else bytes(body) if body is not None else None)
        secret_refs = payload.get("secret_refs") or {}
        if not isinstance(secret_refs, dict) or any(
                not isinstance(k, str) or not isinstance(v, str)
                for k, v in secret_refs.items()):
            raise NetworkPolicyError("secret_refs must be string pairs")
        timeout = min(
            self.timeout_cap, max(0.1, float(payload.get("timeout") or 30.0)))
        request = CapabilityRequest(
            right="network.http",
            selector=validated.url,
            destination=validated.url,
        )
        return PreparedEffect(
            request=request,
            # Syntactic destination policy is fixed.  DNS/IP policy is checked
            # at enactment and the chosen address is pinned to the connection.
            # Network responses are conservatively private.  This is important
            # for authenticated APIs and makes warm-worker state taint across
            # later invocations.
            facts=MediationFacts(
                destination_verified=True,
                observed_labels=frozenset({DataLabel.USER_PRIVATE}),
            ),
            enact=lambda: self._perform(
                method, validated, dict(headers), raw_body,
                dict(secret_refs), timeout, authority.artifact_digest),
        )

    def _perform(self, method: str, current: ValidatedUrl,
                 headers: dict[str, str], body: bytes | None,
                 secret_refs: dict[str, str], timeout: float,
                 artifact_digest: str) -> dict:
        if secret_refs and self.secret_resolver is None:
            raise NetworkPolicyError("no kernel secret resolver is configured")
        effective_headers = dict(headers)
        for header, reference in secret_refs.items():
            # The raw secret exists only in this kernel adapter and the outbound
            # socket buffer.  It is never returned or logged.
            effective_headers[header] = self.secret_resolver(
                reference, artifact_digest, current.url)
        first_origin = current.origin
        for redirects in range(self.max_redirects + 1):
            response = self._request_once(
                method, current, effective_headers, body, timeout)
            if response["status"] not in _REDIRECTS:
                return response
            location = response["headers"].get("location")
            if not location:
                return response
            if redirects >= self.max_redirects:
                raise NetworkPolicyError("HTTP redirect limit exceeded")
            following = validate_url(urljoin(current.url, location))
            # Cross-origin redirects are a second egress destination and require
            # a new capability request/lease.  Do not silently carry credentials
            # or tainted payloads there.
            if following.origin != first_origin:
                raise NetworkPolicyError(
                    "cross-origin redirect requires a new HTTP request")
            current = following
            if response["status"] == 303 or (
                    response["status"] in {301, 302} and method == "POST"):
                method, body = "GET", None
                effective_headers.pop("Content-Length", None)
                effective_headers.pop("content-length", None)
        raise NetworkPolicyError("unreachable redirect state")

    def _request_once(self, method: str, url: ValidatedUrl,
                      headers: dict[str, str], body: bytes | None,
                      timeout: float) -> dict:
        address = resolve_pinned_address(
            url.host, url.port,
            allow_private=url.host in self.allow_private_hosts)
        connection = _PinnedConnection(
            url, address, timeout=timeout)
        request_headers = dict(headers)
        request_headers.setdefault(
            "Host", url.host if url.port in {80, 443}
            else f"{url.host}:{url.port}")
        request_headers.setdefault("Connection", "close")
        try:
            connection.request(method, url.target, body=body,
                               headers=request_headers)
            response = connection.getresponse()
            content = response.read(self.max_response_bytes + 1)
            if len(content) > self.max_response_bytes:
                raise NetworkPolicyError(
                    f"HTTP response exceeds {self.max_response_bytes} bytes")
            response_headers: dict[str, str] = {}
            for key, value in response.getheaders():
                lower = key.lower()
                if lower not in response_headers:
                    response_headers[lower] = value
            return {
                "status": int(response.status),
                "reason": str(response.reason or ""),
                "headers": response_headers,
                "body": content,
                "url": url.url,
            }
        finally:
            connection.close()


class _PinnedConnection:
    def __init__(self, url: ValidatedUrl, address: str, *, timeout: float):
        self.url = url
        self.address = address
        self.timeout = timeout
        self._connection = None

    def _connect(self):
        if self.url.scheme == "http":
            connection = http.client.HTTPConnection(
                self.address, self.url.port, timeout=self.timeout)
            connection.connect()
            return connection
        connection = http.client.HTTPSConnection(
            self.url.host, self.url.port, timeout=self.timeout,
            context=ssl.create_default_context())
        raw = socket.create_connection(
            (self.address, self.url.port), self.timeout)
        connection.sock = connection._context.wrap_socket(
            raw, server_hostname=self.url.host)
        return connection

    def request(self, *args, **kwargs):
        self._connection = self._connect()
        return self._connection.request(*args, **kwargs)

    def getresponse(self):
        return self._connection.getresponse()

    def close(self):
        if self._connection is not None:
            self._connection.close()


def validate_url(raw: str) -> ValidatedUrl:
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise NetworkPolicyError(f"invalid URL: {exc}") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise NetworkPolicyError("only http and https URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise NetworkPolicyError("URL userinfo is forbidden")
    if not parsed.hostname:
        raise NetworkPolicyError("URL host is required")
    host = parsed.hostname.lower().rstrip(".")
    port = port or (443 if scheme == "https" else 80)
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    normalized = urlunsplit((
        scheme,
        host if port in {80, 443} else f"{host}:{port}",
        parsed.path or "/",
        parsed.query,
        "",
    ))
    return ValidatedUrl(normalized, scheme, host, port, target)


def resolve_pinned_address(host: str, port: int, *,
                           allow_private: bool = False) -> str:
    try:
        answers = socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise NetworkPolicyError(f"DNS resolution failed: {exc}") from exc
    addresses = []
    for answer in answers:
        raw = answer[4][0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if not allow_private and (
                ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            continue
        addresses.append(str(ip))
    if not addresses:
        raise NetworkPolicyError(
            "destination resolved only to forbidden local/reserved addresses")
    return sorted(set(addresses))[0]

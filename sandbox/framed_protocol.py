"""Versioned, length-prefixed protocol for capability workers.

This is the protocol for the new SDK.  ``sandbox.protocol`` remains the
JSON-lines legacy-oracle protocol until old plugins have been migrated.
"""

from __future__ import annotations

import base64
import json
import struct
from dataclasses import dataclass
from typing import Any, BinaryIO

PROTOCOL_VERSION = 1
DEFAULT_MAX_FRAME = 8 * 1024 * 1024
_HEADER = struct.Struct(">I")
_KINDS = frozenset({
    "hello", "ready", "invoke", "capability_request", "capability_result",
    "result", "error", "cancel", "shutdown", "log",
})


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Envelope:
    kind: str
    invocation_id: str
    sequence: int
    artifact_digest: str
    payload: dict[str, Any]
    version: int = PROTOCOL_VERSION

    def to_wire(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "kind": self.kind,
            "invocation_id": self.invocation_id,
            "sequence": self.sequence,
            "artifact_digest": self.artifact_digest,
            "payload": self.payload,
        }

    @classmethod
    def from_wire(cls, wire: Any) -> "Envelope":
        if not isinstance(wire, dict):
            raise ProtocolError("frame payload must be an object")
        expected = {
            "version", "kind", "invocation_id", "sequence",
            "artifact_digest", "payload",
        }
        unknown = set(wire) - expected
        missing = expected - set(wire)
        if unknown or missing:
            raise ProtocolError(
                f"invalid envelope fields; missing={sorted(missing)}, "
                f"unknown={sorted(unknown)}")
        version = wire["version"]
        if version != PROTOCOL_VERSION:
            raise ProtocolError(
                f"unsupported protocol version {version!r}")
        kind = wire["kind"]
        if kind not in _KINDS:
            raise ProtocolError(f"unknown message kind {kind!r}")
        invocation_id = wire["invocation_id"]
        digest = wire["artifact_digest"]
        sequence = wire["sequence"]
        payload = wire["payload"]
        if not isinstance(invocation_id, str) or len(invocation_id) > 200:
            raise ProtocolError("invocation_id must be a bounded string")
        if not isinstance(digest, str) or (
                digest and (len(digest) != 64
                            or any(c not in "0123456789abcdef" for c in digest))):
            raise ProtocolError("artifact_digest must be empty or SHA-256 hex")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise ProtocolError("sequence must be a non-negative integer")
        if not isinstance(payload, dict):
            raise ProtocolError("payload must be an object")
        return cls(
            version=version,
            kind=kind,
            invocation_id=invocation_id,
            sequence=sequence,
            artifact_digest=digest,
            payload=payload,
        )


def encode_frame(envelope: Envelope, *,
                 max_frame: int = DEFAULT_MAX_FRAME) -> bytes:
    raw = json.dumps(
        envelope.to_wire(),
        default=_json_default,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")
    if len(raw) > max_frame:
        raise ProtocolError(f"frame exceeds {max_frame} bytes")
    return _HEADER.pack(len(raw)) + raw


def decode_frame(data: bytes, *, max_frame: int = DEFAULT_MAX_FRAME) -> Envelope:
    if len(data) < _HEADER.size:
        raise ProtocolError("truncated frame header")
    length = _HEADER.unpack(data[:_HEADER.size])[0]
    if length > max_frame:
        raise ProtocolError(f"frame declares more than {max_frame} bytes")
    if len(data) != _HEADER.size + length:
        raise ProtocolError("frame length does not match payload")
    try:
        wire = json.loads(
            data[_HEADER.size:].decode("utf-8"),
            object_hook=_json_object_hook,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"invalid JSON frame: {exc}") from exc
    return Envelope.from_wire(wire)


def write_frame(stream: BinaryIO, envelope: Envelope, *,
                max_frame: int = DEFAULT_MAX_FRAME) -> None:
    stream.write(encode_frame(envelope, max_frame=max_frame))
    stream.flush()


def read_frame(stream: BinaryIO, *,
               max_frame: int = DEFAULT_MAX_FRAME) -> Envelope | None:
    header = _read_exact(stream, _HEADER.size, allow_eof=True)
    if header is None:
        return None
    length = _HEADER.unpack(header)[0]
    if length > max_frame:
        raise ProtocolError(f"frame declares more than {max_frame} bytes")
    body = _read_exact(stream, length, allow_eof=False)
    return decode_frame(header + body, max_frame=max_frame)


def _read_exact(stream: BinaryIO, count: int, *,
                allow_eof: bool) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < count:
        piece = stream.read(count - len(chunks))
        if not piece:
            if allow_eof and not chunks:
                return None
            raise ProtocolError("unexpected EOF inside frame")
        chunks.extend(piece)
    return bytes(chunks)


def _json_default(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return {"$bytes": base64.b64encode(bytes(value)).decode("ascii")}
    raise TypeError(f"value is not protocol-serializable: {type(value).__name__}")


def _json_object_hook(value: dict) -> Any:
    if set(value) == {"$bytes"}:
        encoded = value["$bytes"]
        if not isinstance(encoded, str):
            raise ProtocolError("$bytes must be a base64 string")
        try:
            return base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise ProtocolError("invalid base64 payload") from exc
    return value


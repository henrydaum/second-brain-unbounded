import io

import pytest

from sandbox.framed_protocol import (
    Envelope,
    ProtocolError,
    decode_frame,
    encode_frame,
    read_frame,
    write_frame,
)


def _message(payload=None):
    return Envelope(
        kind="invoke",
        invocation_id="i-1",
        sequence=0,
        artifact_digest="a" * 64,
        payload=payload or {"blob": b"abc"},
    )


def test_frame_round_trip_is_binary_safe():
    encoded = encode_frame(_message())
    assert decode_frame(encoded) == _message()
    stream = io.BytesIO()
    write_frame(stream, _message())
    stream.seek(0)
    assert read_frame(stream) == _message()
    assert read_frame(stream) is None


def test_frame_rejects_truncation_and_oversize():
    encoded = encode_frame(_message())
    with pytest.raises(ProtocolError, match="length"):
        decode_frame(encoded[:-1])
    with pytest.raises(ProtocolError, match="exceeds"):
        encode_frame(_message({"x": "z" * 100}), max_frame=20)


def test_protocol_does_not_stringify_arbitrary_python_objects():
    with pytest.raises(TypeError, match="not protocol-serializable"):
        encode_frame(_message({"bad": object()}))


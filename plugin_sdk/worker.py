"""OS-confined async plugin worker.

This module is never a sandbox by itself.  It must only be launched through a
verified native backend.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import os
import sys
import traceback
from pathlib import Path
from typing import Any, Mapping

# ``python -I`` omits the source directory.  The signed/immutable SDK runtime is
# an explicit read-only mount in the native sandbox policy.
_RUNTIME_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_RUNTIME_ROOT))

from plugin_sdk.context import InvocationContext, ResourceHandle  # noqa: E402
from sandbox.framed_protocol import Envelope, read_frame, write_frame  # noqa: E402
from security.artifacts import build_artifact  # noqa: E402


class _PipeTransport:
    def __init__(self, inp, out, invocation_id: str, digest: str,
                 sequence):
        self.inp = inp
        self.out = out
        self.invocation_id = invocation_id
        self.digest = digest
        self.sequence = sequence

    async def request(self, right: str, payload: Mapping[str, Any]) -> Any:
        seq = self.sequence.next_out()
        write_frame(self.out, Envelope(
            kind="capability_request",
            invocation_id=self.invocation_id,
            sequence=seq,
            artifact_digest=self.digest,
            payload={"right": right, "payload": dict(payload)},
        ))
        response = await asyncio.to_thread(read_frame, self.inp)
        if response is None:
            raise RuntimeError("kernel closed capability channel")
        self.sequence.accept_in(response)
        if response.kind != "capability_result":
            raise RuntimeError(
                f"expected capability_result, got {response.kind}")
        return response.payload.get("value")


class _Sequence:
    def __init__(self):
        self.outgoing = 0
        self.incoming = 0

    def next_out(self) -> int:
        value = self.outgoing
        self.outgoing += 1
        return value

    def accept_in(self, envelope: Envelope) -> None:
        if envelope.sequence != self.incoming:
            raise RuntimeError("non-monotonic kernel sequence")
        self.incoming += 1


async def _invoke(handler, params: dict, resources: dict,
                  transport: _PipeTransport):
    context = InvocationContext(
        transport,
        resources={
            name: ResourceHandle(
                token=str(value["token"]), selector=str(value["selector"]))
            for name, value in resources.items()
        },
    )
    result = handler(context, params)
    if not inspect.isawaitable(result):
        raise TypeError("clean SDK handlers must be async functions")
    return await result


def _handler(artifact_root: Path, entrypoint: str):
    module_name, function_name = entrypoint.split(":", 1)
    sys.path.insert(0, str(artifact_root))
    module = importlib.import_module(module_name)
    value = getattr(module, function_name, None)
    if not callable(value):
        raise RuntimeError(f"entrypoint is not callable: {entrypoint}")
    return value


async def serve(artifact_root: Path, digest: str, kind: str, name: str) -> int:
    # Capture the dedicated binary protocol before any extension import.  Even
    # import-time prints are diverted to diagnostics, never protocol traffic.
    inp = sys.stdin.buffer
    out = sys.stdout.buffer
    sys.stdout = sys.stderr
    artifact = build_artifact(artifact_root)
    if artifact.identity.digest != digest:
        raise RuntimeError("worker artifact digest mismatch")
    handler_manifest = artifact.manifest.handler(kind, name)
    if handler_manifest is None:
        raise RuntimeError(f"manifest has no handler {kind}:{name}")
    handler = _handler(artifact_root, handler_manifest.entrypoint)

    write_frame(out, Envelope(
        kind="ready", invocation_id="", sequence=0,
        artifact_digest=digest,
        payload={"plugin_id": artifact.identity.plugin_id,
                 "handler": f"{kind}:{name}"},
    ))
    while True:
        message = await asyncio.to_thread(read_frame, inp)
        if message is None or message.kind == "shutdown":
            return 0
        if message.kind != "invoke":
            raise RuntimeError(f"expected invoke, got {message.kind}")
        if message.artifact_digest != digest:
            raise RuntimeError("invocation artifact digest mismatch")
        invocation_id = message.invocation_id
        sequence = _Sequence()
        sequence.incoming = message.sequence + 1
        # The worker's ready frame occupied sequence zero outside invocations;
        # per-invocation child sequences begin at zero.
        sequence.outgoing = 0
        try:
            result = await _invoke(
                handler,
                dict(message.payload.get("arguments") or {}),
                dict(message.payload.get("resources") or {}),
                _PipeTransport(inp, out, invocation_id, digest, sequence),
            )
            write_frame(out, Envelope(
                kind="result", invocation_id=invocation_id,
                sequence=sequence.next_out(), artifact_digest=digest,
                payload={"value": result},
            ))
        except BaseException as exc:  # report; parent decides worker lifetime
            write_frame(out, Envelope(
                kind="error", invocation_id=invocation_id,
                sequence=sequence.next_out(), artifact_digest=digest,
                payload={
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                    "traceback": "".join(traceback.format_exception(
                        type(exc), exc, exc.__traceback__))[-4000:],
                },
            ))


def main() -> int:
    if os.environ.get("SECOND_BRAIN_WORKER_CONFIRMED") != "1":
        raise RuntimeError(
            "worker was not launched by a verified sandbox backend")
    if len(sys.argv) != 5:
        raise RuntimeError(
            "usage: worker.py ARTIFACT_ROOT DIGEST KIND NAME")
    return asyncio.run(serve(
        Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]))


if __name__ == "__main__":
    raise SystemExit(main())

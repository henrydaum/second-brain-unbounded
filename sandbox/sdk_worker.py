"""Parent client and warm pool for the clean-break async SDK worker."""

from __future__ import annotations

import asyncio
import sys
import tempfile
import threading
import uuid
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

from sandbox.backends import NativeSandboxBackend, SandboxPolicy
from sandbox.framed_protocol import Envelope, read_frame, write_frame
from security.artifacts import PluginArtifact
from security.broker import CapabilityBroker
from security.capabilities import AuthorityContext
from security.capabilities import DataLabel
from security.manifest import HandlerManifest

_WORKER = Path(__file__).resolve().parents[1] / "plugin_sdk" / "worker.py"


class WorkerProtocolError(RuntimeError):
    pass


class SDKWorkerClient:
    def __init__(self, artifact: PluginArtifact, handler: HandlerManifest,
                 backend: NativeSandboxBackend, broker: CapabilityBroker,
                 authority_factory, scratch_root: str | Path):
        self.artifact = artifact
        self.handler = handler
        self.backend = backend
        self.broker = broker
        self.authority_factory = authority_factory
        self.scratch_root = Path(scratch_root)
        self._invoke_lock = threading.Lock()
        self._state_taint = frozenset({DataLabel.PUBLIC})
        self._parent_sequence = 0
        policy = SandboxPolicy(
            artifact_root=artifact.root,
            scratch_root=self.scratch_root,
            memory_mb=artifact.manifest.budgets.memory_mb,
            cpu_seconds=artifact.manifest.budgets.cpu_seconds,
            wall_seconds=artifact.manifest.budgets.wall_seconds,
        )
        self.proc = backend.launch(
            policy,
            [sys.executable, "-I", "-B", str(_WORKER),
             str(artifact.root), artifact.identity.digest,
             handler.kind, handler.name],
            env={"SECOND_BRAIN_WORKER_CONFIRMED": "1"},
        )
        ready = read_frame(self.proc.stdout)
        if (ready is None or ready.kind != "ready"
                or ready.artifact_digest != artifact.identity.digest):
            self.close()
            raise WorkerProtocolError("worker failed authenticated handshake")
        self._stderr: list[bytes] = []
        threading.Thread(
            target=self._drain_stderr, daemon=True,
            name=f"plugin-stderr-{handler.name}").start()

    def _drain_stderr(self):
        for line in iter(self.proc.stderr.readline, b""):
            self._stderr.append(line[-4096:])
            del self._stderr[:-100]

    @property
    def alive(self) -> bool:
        return self.proc.poll() is None

    async def invoke(self, arguments: Mapping[str, Any], *,
                     resources: Mapping[str, Mapping[str, str]] | None = None,
                     authority: AuthorityContext | None = None) -> Any:
        async with _held(self._invoke_lock):
            if not self.alive:
                raise WorkerProtocolError("worker is not running")
            invocation_id = uuid.uuid4().hex
            authority = authority or self.authority_factory(
                self.artifact, self.handler)
            authority = replace(
                authority,
                taint=frozenset((*authority.taint, *self._state_taint)),
            )
            parent_sequence = 0
            await asyncio.to_thread(
                write_frame, self.proc.stdin, Envelope(
                    kind="invoke", invocation_id=invocation_id,
                    sequence=parent_sequence,
                    artifact_digest=self.artifact.identity.digest,
                    payload={
                        "arguments": dict(arguments),
                        "resources": dict(resources or {}),
                    },
                ))
            parent_sequence += 1
            expected_child = 0
            try:
                while True:
                    message = await asyncio.to_thread(
                        read_frame, self.proc.stdout)
                    if message is None:
                        raise WorkerProtocolError("worker closed protocol stream")
                    if message.artifact_digest != self.artifact.identity.digest:
                        raise WorkerProtocolError("worker changed artifact identity")
                    if message.invocation_id != invocation_id:
                        raise WorkerProtocolError("worker changed invocation identity")
                    if message.sequence != expected_child:
                        raise WorkerProtocolError("non-monotonic worker sequence")
                    expected_child += 1
                    if message.kind == "capability_request":
                        right = message.payload.get("right")
                        payload = message.payload.get("payload")
                        if not isinstance(right, str) or not isinstance(payload, dict):
                            raise WorkerProtocolError(
                                "malformed capability request")
                        value = await self.broker.fulfill(
                            invocation_id=invocation_id,
                            manifest=self.artifact.manifest,
                            authority=authority,
                            right=right,
                            payload=payload,
                        )
                        await asyncio.to_thread(
                            write_frame, self.proc.stdin, Envelope(
                                kind="capability_result",
                                invocation_id=invocation_id,
                                sequence=parent_sequence,
                                artifact_digest=self.artifact.identity.digest,
                                payload={"value": value},
                            ))
                        parent_sequence += 1
                        continue
                    if message.kind == "result":
                        return message.payload.get("value")
                    if message.kind == "error":
                        raise WorkerProtocolError(
                            f"{message.payload.get('error_type')}: "
                            f"{message.payload.get('message')}")
                    raise WorkerProtocolError(
                        f"unexpected worker message {message.kind}")
            except BaseException:
                await asyncio.to_thread(self.close)
                raise
            finally:
                self._state_taint = frozenset((
                    *self._state_taint,
                    *self.broker.invocation_taint(
                        invocation_id, authority.taint),
                ))
                self.broker.finish_invocation(invocation_id)

    async def proxy_invoke(self, _artifact: PluginArtifact,
                           _handler: HandlerManifest,
                           arguments: Mapping[str, Any]) -> Any:
        return await self.invoke(arguments)

    def close(self) -> None:
        if getattr(self, "proc", None) is None:
            return
        try:
            if self.proc.poll() is None:
                write_frame(self.proc.stdin, Envelope(
                    kind="shutdown", invocation_id="", sequence=0,
                    artifact_digest=self.artifact.identity.digest, payload={}))
                self.proc.wait(timeout=2)
        except Exception:
            self.proc.kill()


class SDKWorkerPool:
    def __init__(self, backend: NativeSandboxBackend,
                 broker: CapabilityBroker, authority_factory,
                 scratch_root: str | Path):
        self.backend = backend
        self.broker = broker
        self.authority_factory = authority_factory
        self.scratch_root = Path(scratch_root)
        self._workers: dict[tuple[str, str, str], SDKWorkerClient] = {}
        self._locks: dict[tuple[str, str, str], threading.Lock] = {}

    async def invoker_for(self, artifact: PluginArtifact,
                          _backend=None):
        # Create and handshake every declared handler before registry activation.
        clients = {}
        for handler in artifact.manifest.handlers:
            key = (artifact.identity.digest, handler.kind, handler.name)
            client = await self._client(artifact, handler)
            clients[(handler.kind, handler.name)] = client

        async def invoke(_artifact, handler, arguments, invocation=None):
            options = invocation or {}
            client = clients[(handler.kind, handler.name)]
            if not client.alive:
                client = await self._client(artifact, handler)
                clients[(handler.kind, handler.name)] = client
            return await client.invoke(
                arguments,
                resources=options.get("resources"),
                authority=options.get("authority"))

        return invoke

    async def _client(
        self,
        artifact: PluginArtifact,
        handler: HandlerManifest,
    ) -> SDKWorkerClient:
        key = (artifact.identity.digest, handler.kind, handler.name)
        lock = self._locks.setdefault(key, threading.Lock())
        async with _held(lock):
            client = self._workers.get(key)
            if client is not None and client.alive:
                return client
            scratch = self.scratch_root / artifact.identity.digest / (
                f"{handler.kind}-{handler.name}")
            client = await asyncio.to_thread(
                SDKWorkerClient,
                artifact, handler, self.backend, self.broker,
                self.authority_factory, scratch)
            self._workers[key] = client
            return client

    def close(self) -> None:
        for worker in list(self._workers.values()):
            worker.close()
        self._workers.clear()
        self._locks.clear()


@asynccontextmanager
async def _held(lock: threading.Lock):
    await asyncio.to_thread(lock.acquire)
    try:
        yield
    finally:
        lock.release()

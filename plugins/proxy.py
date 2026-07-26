"""Kernel-owned metadata proxies for manifest plugins.

A proxy contains no extension object and imports no extension module.  Runtime
workers are reached only through the supplied invoker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping

from security.artifacts import PluginArtifact
from security.manifest import HandlerManifest


class ProxyError(RuntimeError):
    pass


Invoker = Callable[
    [PluginArtifact, HandlerManifest, Mapping[str, Any], Any], Awaitable[Any]]


@dataclass(frozen=True)
class PluginProxy:
    artifact: PluginArtifact
    handler: HandlerManifest
    invoker: Invoker

    @property
    def name(self) -> str:
        return self.handler.name

    @property
    def family(self) -> str:
        return self.handler.kind

    @property
    def artifact_digest(self) -> str:
        return self.artifact.identity.digest

    async def invoke(self, arguments: Mapping[str, Any] | None = None, *,
                     invocation=None) -> Any:
        if not self.artifact.verify():
            raise ProxyError(
                f"artifact {self.artifact.identity.plugin_id} changed after activation")
        return await self.invoker(
            self.artifact, self.handler, dict(arguments or {}), invocation)

    def tool_schema(self) -> dict:
        if self.handler.kind != "tool":
            raise ProxyError("only tool proxies expose an LLM tool schema")
        return {
            "type": "function",
            "function": {
                "name": self.handler.name,
                "description": self.handler.description,
                "parameters": dict(self.handler.schema),
            },
        }


class ProxyRegistry:
    """Atomic artifact registration with collision checks."""

    def __init__(self):
        self._by_identity: dict[tuple[str, str], PluginProxy] = {}
        self._by_artifact: dict[str, set[tuple[str, str]]] = {}

    def snapshot(self) -> dict[tuple[str, str], PluginProxy]:
        return dict(self._by_identity)

    def stage(self, artifact: PluginArtifact, invoker: Invoker) -> tuple[PluginProxy, ...]:
        return tuple(
            PluginProxy(artifact, handler, invoker)
            for handler in artifact.manifest.handlers)

    def activate(self, staged: tuple[PluginProxy, ...]) -> None:
        if not staged:
            raise ProxyError("cannot activate an empty proxy set")
        artifact = staged[0].artifact
        if any(item.artifact.identity != artifact.identity for item in staged):
            raise ProxyError("staged proxies do not belong to one artifact")
        new_keys = {(item.family, item.name) for item in staged}
        if len(new_keys) != len(staged):
            raise ProxyError("staged proxies contain duplicate identities")
        previous_keys = self._by_artifact.get(
            artifact.identity.plugin_id, set())
        collisions = [
            key for key in new_keys
            if key in self._by_identity and key not in previous_keys
        ]
        if collisions:
            raise ProxyError(f"handler collisions: {sorted(collisions)}")

        replacement = dict(self._by_identity)
        for key in previous_keys:
            replacement.pop(key, None)
        for proxy in staged:
            replacement[(proxy.family, proxy.name)] = proxy
        self._by_identity = replacement
        self._by_artifact[artifact.identity.plugin_id] = new_keys

    def deactivate(self, plugin_id: str) -> tuple[PluginProxy, ...]:
        keys = self._by_artifact.pop(plugin_id, set())
        removed = tuple(
            self._by_identity[key] for key in keys if key in self._by_identity)
        replacement = dict(self._by_identity)
        for key in keys:
            replacement.pop(key, None)
        self._by_identity = replacement
        return removed

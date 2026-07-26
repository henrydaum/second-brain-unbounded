"""Friendly async capability clients over a deliberately tiny transport."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol


class CapabilityDenied(PermissionError):
    pass


class CapabilityTransport(Protocol):
    async def request(self, right: str, payload: Mapping[str, Any]) -> Any:
        """Send one typed request and return its value or raise."""


@dataclass(frozen=True)
class ResourceHandle:
    """Opaque token.  It intentionally exposes no host path."""

    token: str
    selector: str


class _Domain:
    def __init__(self, transport: CapabilityTransport):
        self._transport = transport

    async def _call(self, right: str, **payload):
        response = await self._transport.request(right, payload)
        if isinstance(response, dict) and response.get("denied"):
            raise CapabilityDenied(response.get("error") or "capability denied")
        return response


class FilesClient(_Domain):
    async def read_text(self, resource: ResourceHandle, relative_path: str,
                        *, encoding: str = "utf-8") -> str:
        return await self._call(
            "files.read", resource=resource.token,
            selector=_join(resource.selector, relative_path), encoding=encoding)

    async def list(self, resource: ResourceHandle, relative_path: str = "",
                   *, recursive: bool = False) -> list[dict]:
        return await self._call(
            "files.list", resource=resource.token,
            selector=_join(resource.selector, relative_path),
            recursive=bool(recursive))

    async def stat(self, resource: ResourceHandle,
                   relative_path: str = "") -> dict:
        return await self._call(
            "files.stat", resource=resource.token,
            selector=_join(resource.selector, relative_path))

    async def write_text(self, resource: ResourceHandle, relative_path: str,
                         content: str, *, encoding: str = "utf-8") -> dict:
        return await self._call(
            "files.write", resource=resource.token,
            selector=_join(resource.selector, relative_path),
            content=content, encoding=encoding)

    async def delete(self, resource: ResourceHandle,
                     relative_path: str) -> dict:
        return await self._call(
            "files.delete", resource=resource.token,
            selector=_join(resource.selector, relative_path))

    async def move(self, resource: ResourceHandle, source: str,
                   destination: str) -> dict:
        return await self._call(
            "files.move", resource=resource.token,
            selector=_join(resource.selector, source),
            destination_selector=_join(resource.selector, destination))


class DataClient(_Domain):
    async def get(self, resource: ResourceHandle, key: str) -> Any:
        return await self._call(
            "data.read", resource=resource.token, selector=resource.selector,
            operation="get", key=key)

    async def list(self, resource: ResourceHandle, *,
                   prefix: str = "", limit: int = 100) -> list[dict]:
        return await self._call(
            "data.read", resource=resource.token, selector=resource.selector,
            operation="list", prefix=prefix, limit=int(limit))

    async def put(self, resource: ResourceHandle, key: str, value: Any,
                  *, expected_version: int | None = None) -> Any:
        return await self._call(
            "data.write", resource=resource.token, selector=resource.selector,
            operation="put", key=key, value=value,
            expected_version=expected_version)

    async def delete(self, resource: ResourceHandle, key: str,
                     *, expected_version: int | None = None) -> Any:
        return await self._call(
            "data.write", resource=resource.token, selector=resource.selector,
            operation="delete", key=key, expected_version=expected_version)

    async def view(self, resource: ResourceHandle, name: str,
                   params: Mapping[str, Any] | None = None) -> Any:
        return await self._call(
            "data.read", resource=resource.token, selector=resource.selector,
            operation="view", view=name, params=dict(params or {}))


class NetworkClient(_Domain):
    async def http(self, *, method: str, url: str,
                   headers: Mapping[str, str] | None = None,
                   body: str | bytes | None = None,
                   secret_refs: Mapping[str, str] | None = None) -> dict:
        return await self._call(
            "network.http", selector=url, destination=url, method=method,
            headers=dict(headers or {}), body=body,
            secret_refs=dict(secret_refs or {}))


class ModelsClient(_Domain):
    async def complete(self, prompt: str, *, system: str = "",
                       schema: Mapping[str, Any] | None = None,
                       profile: str = "") -> Any:
        return await self._call(
            "models.complete", selector=profile or "default",
            destination=profile or "default", prompt=prompt, system=system,
            schema=dict(schema) if schema else None)

    async def embed(self, inputs: list[str], *, profile: str = "") -> Any:
        return await self._call(
            "models.embed", selector=profile or "default",
            destination=profile or "default", inputs=list(inputs))


class RuntimeClient(_Domain):
    async def ask_user(self, prompt: str, *, title: str = "",
                       choices: list[str] | None = None) -> str:
        return await self._call(
            "runtime.ask_user", selector="current_session",
            prompt=prompt, title=title, choices=choices)

    async def call_tool(self, name: str,
                        arguments: Mapping[str, Any]) -> Any:
        return await self._call(
            "runtime.call_tool", selector=name, name=name,
            arguments=dict(arguments))

    async def spawn_agent(self, *, prompt: str,
                          delegated_resources: list[ResourceHandle] | None = None,
                          notify: bool = False) -> Any:
        return await self._call(
            "runtime.spawn_agent", selector="child",
            prompt=prompt,
            delegated_resources=[
                item.token for item in (delegated_resources or [])],
            notify=bool(notify))


class ProcessClient(_Domain):
    async def run(self, argv: list[str], *,
                  workspace: ResourceHandle | None = None,
                  timeout: float = 60.0) -> dict:
        return await self._call(
            "process.run",
            resource=workspace.token if workspace else "",
            selector=workspace.selector if workspace else "empty",
            argv=list(argv), timeout=float(timeout))


class OutputsClient(_Domain):
    async def attach(self, resource: ResourceHandle,
                     relative_path: str) -> dict:
        return await self._call(
            "outputs.attach", resource=resource.token,
            selector=_join(resource.selector, relative_path))


class InvocationContext:
    """The only object an SDK handler needs."""

    def __init__(self, transport: CapabilityTransport, *,
                 resources: Mapping[str, ResourceHandle] | None = None):
        self.resources = dict(resources or {})
        self.files = FilesClient(transport)
        self.data = DataClient(transport)
        self.network = NetworkClient(transport)
        self.models = ModelsClient(transport)
        self.runtime = RuntimeClient(transport)
        self.process = ProcessClient(transport)
        self.outputs = OutputsClient(transport)


def _join(root: str, relative: str) -> str:
    relative = str(relative or "").replace("\\", "/")
    parts = [item for item in relative.split("/") if item not in {"", "."}]
    if any(item == ".." for item in parts):
        raise ValueError("relative selector may not contain '..'")
    prefix = root.rstrip("/")
    suffix = "/".join(parts)
    return f"{prefix}/{suffix}" if suffix else prefix

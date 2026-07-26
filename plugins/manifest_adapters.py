"""Adapters from kernel registries to data-only PluginProxy handlers."""

from __future__ import annotations

import asyncio
from typing import Any

from plugins.BaseTool import BaseTool, ToolResult
from plugins.proxy import PluginProxy
from security.capabilities import AuthorityContext, ProvenanceChain


class ManifestToolAdapter(BaseTool):
    """A kernel-owned BaseTool facade; no extension class is imported."""

    contract = "legacy"  # ``perform`` is fully overridden below.

    def __init__(self, proxy: PluginProxy, security_runtime):
        if proxy.family != "tool":
            raise ValueError("tool adapter requires a tool proxy")
        self.proxy = proxy
        self.security_runtime = security_runtime
        self.name = proxy.name
        self.description = proxy.handler.description
        self.parameters = dict(proxy.handler.schema)
        self.requires_services = []
        self.dependencies_files = []
        self.dependencies_pip = []
        self.dependencies_tools = []
        self.config_settings = []
        self.declared_requests = []
        self.max_calls = 3
        self.background_safe = True
        self._source_path = str(proxy.artifact.root)

    def to_schema(self) -> dict:
        return self.proxy.tool_schema()

    def perform(self, context, **kwargs) -> ToolResult:
        authority = self._authority(context)
        resources = {}
        for ref in self.security_runtime.resources.for_authority(authority):
            alias = ref.alias or _alias(ref.selector)
            if alias and alias not in resources:
                resources[alias] = {
                    "token": ref.token,
                    "selector": ref.selector.rstrip("/*"),
                }
        try:
            value = asyncio.run(self.proxy.invoke(
                kwargs,
                invocation={"authority": authority, "resources": resources},
            ))
        except Exception as exc:
            return ToolResult.failed(str(exc))
        if isinstance(value, dict):
            if value.get("success") is False:
                return ToolResult.failed(str(value.get("error") or "plugin failed"))
            attachment_paths = []
            for item in value.get("attachments") or []:
                token = (
                    item.get("attachment") if isinstance(item, dict) else item)
                if not isinstance(token, str):
                    return ToolResult.failed(
                        "plugin returned a malformed attachment handle")
                attachment = self.security_runtime.attachments.resolve(
                    token, authority)
                if attachment is None:
                    return ToolResult.failed(
                        "plugin returned an absent or foreign attachment handle")
                attachment_paths.append(str(attachment.path))
            return ToolResult(
                success=True,
                llm_summary=str(value.get("summary") or ""),
                data=value.get("data", value),
                attachment_paths=attachment_paths,
            )
        return ToolResult(success=True, llm_summary=str(value), data=value)

    def _authority(self, context) -> AuthorityContext:
        principal = str(getattr(context, "principal", "agent") or "agent")
        digest = self.proxy.artifact_digest
        session_key = getattr(context, "session_key", None)
        runtime = getattr(context, "runtime", None)
        conversation_id = getattr(context, "conversation_id", None)
        session = None
        if runtime is not None and session_key:
            session = (getattr(runtime, "sessions", {}) or {}).get(session_key)
        if conversation_id is None and session is not None:
            conversation_id = getattr(session, "conversation_id", None)
        user_id = getattr(context, "user_id", None)
        if user_id is None and session is not None:
            user_id = getattr(session, "user_id", None)
        if user_id is None and runtime is not None and session_key:
            user_id = runtime.session_user_id(session_key)
        unattended = bool(
            runtime is not None and session_key
            and not runtime.is_attended(session_key))
        return AuthorityContext(
            artifact_digest=digest,
            principal=principal,
            provenance=ProvenanceChain(principal).enter(
                digest, f"tool:{self.name}"),
            user_id=user_id,
            session_key=session_key,
            conversation_id=conversation_id,
            unattended=unattended,
        )


def register_manifest_tools(security_runtime, tool_registry) -> list[str]:
    registered = []
    for (family, _name), proxy in security_runtime.proxies.snapshot().items():
        if family != "tool":
            continue
        tool_registry.register(ManifestToolAdapter(proxy, security_runtime))
        registered.append(proxy.name)
    return registered


def _alias(selector: str) -> str:
    prefix = selector.rstrip("/*")
    return prefix.split("/", 1)[0] if prefix else ""

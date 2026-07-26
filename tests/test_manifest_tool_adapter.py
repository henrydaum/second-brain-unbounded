import asyncio
from types import SimpleNamespace

from plugins.manifest_adapters import ManifestToolAdapter
from plugins.proxy import PluginProxy
from security.artifacts import build_artifact
from security.capabilities import ResourceRegistry


def test_manifest_tool_adapter_exposes_schema_and_kernel_authority(tmp_path):
    root = tmp_path / "plugin"
    root.mkdir()
    (root / "plugin.toml").write_text("""
schema_version = 1
id = "example.tool"
version = "1"
runtime = "python"

[[handlers]]
kind = "tool"
name = "hello"
entrypoint = "plugin:run"
description = "Say hello"

[handlers.schema]
type = "object"
""", encoding="utf-8")
    (root / "plugin.lock").write_text(
        "lock_version = 1\n", encoding="utf-8")
    (root / "plugin.py").write_text("pass\n", encoding="utf-8")
    artifact = build_artifact(root)
    seen = {}

    async def invoke(_artifact, _handler, args, invocation):
        seen.update(invocation)
        return {"summary": "hello", "data": args}

    proxy = PluginProxy(artifact, artifact.manifest.handlers[0], invoke)
    security = SimpleNamespace(
        resources=ResourceRegistry(),
        attachments=SimpleNamespace(resolve=lambda *_: None),
    )
    adapter = ManifestToolAdapter(proxy, security)
    context = SimpleNamespace(
        principal="agent", session_key=None, runtime=None,
        user_id=7, conversation_id=9)
    result = adapter.perform(context, name="world")
    assert result.success and result.llm_summary == "hello"
    assert seen["authority"].artifact_digest == artifact.identity.digest
    assert seen["authority"].principal == "agent"
    assert adapter.to_schema()["function"]["name"] == "hello"

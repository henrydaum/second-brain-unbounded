import asyncio
from dataclasses import replace

from plugins.proxy import PluginProxy
from security.artifacts import build_artifact
from security.hooks import HookAction, TypedHookRegistry


def _proxy(tmp_path, response):
    root = tmp_path / "hook"
    root.mkdir()
    (root / "plugin.toml").write_text("""
schema_version = 1
id = "example.hook"
version = "1"
runtime = "python"

[[handlers]]
kind = "hook"
name = "guard"
entrypoint = "plugin:run"
subscriptions = ["vet_permission"]
""", encoding="utf-8")
    (root / "plugin.lock").write_text(
        "lock_version = 1\n", encoding="utf-8")
    (root / "plugin.py").write_text("pass\n", encoding="utf-8")
    artifact = build_artifact(root)

    async def invoke(_artifact, _handler, _args, _invocation=None):
        return response
    return PluginProxy(artifact, artifact.manifest.handlers[0], invoke)


def test_permission_hook_cannot_transform_a_denial_into_allow(tmp_path):
    registry = TypedHookRegistry()
    registry.add(
        "vet_permission",
        _proxy(tmp_path, {"action": "transform", "patch": {"allow": True}}))
    results = asyncio.run(
        registry.consult("vet_permission", {"right": "process.host_run"}))
    assert results[0].action == HookAction.ABSTAIN


def test_hook_payloads_and_results_are_serializable_data(tmp_path):
    registry = TypedHookRegistry()
    registry.add(
        "turn_start",
        _proxy(tmp_path, {"action": "transform", "patch": {"note": "hello"}}))
    result = asyncio.run(registry.consult("turn_start", {"text": "hi"}))[0]
    assert result.action == HookAction.TRANSFORM
    assert result.patch == {"note": "hello"}

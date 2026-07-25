"""Tests for the plugin hot-reload substrate (``service_plugin_watcher``).

The watcher is the install/uninstall mechanism the future plugin store builds
on: it scans the plugin dirs, debounces filesystem events, and loads/unloads
plugins by file presence. These tests fake the loader and assert the
scan/add/edit/delete/ignore paths and the user-facing chat notices.
"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from events.event_bus import bus
from events.event_channels import CHAT_MESSAGE_PUSHED
from plugins import plugin_discovery
from plugins.services.service_plugin_watcher import PluginWatcherService


class _ToolRegistry:
    """Tool registry."""
    def __init__(self):
        """Initialize the tool registry."""
        self.tools = {}
        self.unregistered = []

    def unregister(self, name):
        """Unregister tool registry."""
        self.unregistered.append(name)

    def register(self, tool):
        """Register tool registry."""
        self.tools[tool.name] = tool


def _watched_dir(tmp_path, monkeypatch, plugin_type="tool"):
    """Create a watched plugin dir under tmp_path and patch it in."""
    directory = tmp_path / "watched"
    directory.mkdir()
    _patch_plugin_dir(monkeypatch, directory, plugin_type)
    return directory


def _patch_plugin_dir(monkeypatch, directory, plugin_type="tool"):
    """Internal helper to handle patch plugin dir."""
    import plugins.helpers.plugin_paths as paths

    config = dict(paths.PLUGIN_CONFIG)
    directory = Path(directory).resolve()
    family = directory.name
    root = paths.PluginRoot("test", directory.parent, "test_plugins")
    prefix = paths.PLUGIN_FAMILIES[plugin_type][1]
    config[plugin_type] = (paths.PluginDir(root, plugin_type, family, prefix),)
    monkeypatch.setattr(paths, "PLUGIN_CONFIG", config)


def _patch_tool_discovery(monkeypatch, roots):
    """Patch tool discovery to use test roots."""
    import plugins.helpers.plugin_paths as paths

    plugin_roots = tuple(paths.PluginRoot(name, Path(root), module, built_in) for name, root, module, built_in in roots)
    config = dict(paths.PLUGIN_CONFIG)
    config["tool"] = tuple(paths.PluginDir(root, "tool", "tools", "tool_") for root in plugin_roots)
    monkeypatch.setattr(paths, "PLUGIN_ROOTS", plugin_roots)
    monkeypatch.setattr(paths, "PLUGIN_CONFIG", config)
    monkeypatch.setattr(plugin_discovery, "PLUGIN_ROOTS", plugin_roots)
    monkeypatch.setattr(plugin_discovery, "_TOOL_CONFIG", plugin_discovery._discovery_config("tool"))


class _CommandRegistry:
    """Command registry."""
    def __init__(self):
        """Initialize command registry."""
        self._commands = {}

    def register(self, command):
        """Register command."""
        self._commands[command.name] = command

    def unregister(self, name):
        """Unregister command."""
        self._commands.pop(name, None)

    def to_callable_specs(self):
        """Return command specs."""
        return dict(self._commands)



# ── the reload surface (kernel side of ReloadPlugin) ─────────────────────
#
# Everything the watcher used to do *around* a load lives here now: inferring
# the family, refusing non-plugin files, rewiring peer services, refreshing
# command specs, announcing the outcome. These tests drive it directly, because
# it is where the behaviour is -- the watcher below only decides *which* paths.


def _context(monkeypatch, **kwargs):
    """A context carrying only the registries a reload touches."""
    ctx = SimpleNamespace(config={}, services={}, tool_registry=None, orchestrator=None,
                          command_registry=None, runtime=None)
    for key, value in kwargs.items():
        setattr(ctx, key, value)
    monkeypatch.setattr("plugins.helpers.plugin_reload._reconcile_config", lambda _c: None)
    return ctx


def _reloader(monkeypatch, **kwargs):
    """The reload callable, over a context built from ``kwargs``."""
    from plugins.helpers.plugin_reload import build_reload_plugin

    return build_reload_plugin(_context(monkeypatch, **kwargs))


def test_reload_loads_a_plugin_by_path(tmp_path, monkeypatch):
    calls = []
    path = _watched_dir(tmp_path, monkeypatch) / "tool_demo.py"
    path.write_text("x", encoding="utf-8")
    monkeypatch.setattr("plugins.plugin_discovery.load_single_plugin",
                        lambda *a, **k: calls.append((a, k)) or ("demo", None))

    result = _reloader(monkeypatch, tool_registry=_ToolRegistry())(str(path), "reload")

    assert result["ok"] and result["name"] == "demo"
    assert calls[0][0][0] == "tool"
    assert calls[0][0][1] == path.resolve()


def test_reload_announces_success_and_failure(tmp_path, monkeypatch):
    messages = []
    path = _watched_dir(tmp_path, monkeypatch) / "tool_demo.py"
    path.write_text("x", encoding="utf-8")
    unsub = bus.subscribe(CHAT_MESSAGE_PUSHED, lambda p: messages.append(p["message"]))
    try:
        monkeypatch.setattr("plugins.plugin_discovery.load_single_plugin",
                            lambda *a, **k: ("demo", None))
        _reloader(monkeypatch)(str(path), "reload")
        monkeypatch.setattr("plugins.plugin_discovery.load_single_plugin",
                            lambda *a, **k: (None, "boom"))
        result = _reloader(monkeypatch)(str(path), "reload")

        assert messages == ["✓ Registered plugin: demo",
                            "✕ Plugin registration failed: tool_demo.py\nboom"]
        assert result["ok"] is False and result["error"] == "boom"
    finally:
        unsub()


def test_reload_refuses_a_file_that_is_not_a_plugin(tmp_path, monkeypatch):
    """The family is inferred kernel-side, so a plugin naming a wrong path gets
    a refusal rather than an import."""
    calls = []
    path = _watched_dir(tmp_path, monkeypatch) / "demo.py"
    path.write_text("x", encoding="utf-8")
    monkeypatch.setattr("plugins.plugin_discovery.load_single_plugin",
                        lambda *a, **k: calls.append(a) or ("demo", None))

    result = _reloader(monkeypatch)(str(path), "reload")

    assert not calls
    assert result["ok"] is False and result["error"]


def test_unload_deregisters_by_source_and_announces(tmp_path, monkeypatch):
    calls, messages = [], []
    path = _watched_dir(tmp_path, monkeypatch) / "tool_demo.py"
    path.write_text("x", encoding="utf-8")
    unsub = bus.subscribe(CHAT_MESSAGE_PUSHED, lambda p: messages.append(p["message"]))
    try:
        registry = _ToolRegistry()
        registry.tools["demo"] = type("DemoTool", (), {"_source_path": str(path.resolve())})()
        monkeypatch.setattr("plugins.plugin_discovery.unload_plugin",
                            lambda *a, **k: calls.append((a, k)))

        _reloader(monkeypatch, tool_registry=registry)(str(path), "unload")

        assert calls[0][0][0] == "tool"
        assert calls[0][1]["source_path"] == str(path.resolve())
        assert messages == ["Deregistered plugin: demo"]
    finally:
        unsub()


def test_reload_accepts_llm_backend_provider(tmp_path, monkeypatch):
    """Verify service-family LLM backend files refresh profiles instead of failing."""
    from plugins.services.service_llm import LLMRouter
    messages = []
    path = _watched_dir(tmp_path, monkeypatch, "service") / "service_fake_llm.py"
    unsub = bus.subscribe(CHAT_MESSAGE_PUSHED, lambda p: messages.append(p["message"]))
    try:
        path.write_text(
            "from plugins.services.service_llm import BaseLLM, LLMResponse\n\n"
            "class FakeBackend(BaseLLM):\n"
            "    is_llm_backend = True\n"
            "    def __init__(self, model_name, api_key=None, base_url=None): super().__init__(); self.model_name = model_name\n"
            "    def _load(self): self.loaded = True; return True\n"
            "    def unload(self): self.loaded = False\n"
            "    def invoke(self, messages, attachments=None, **kwargs): return LLMResponse(content='ok')\n"
            "    def stream(self, messages, attachments=None, **kwargs): return iter(())\n"
            "    def chat_with_tools(self, messages, tools=None, **kwargs): return LLMResponse(content='ok')\n",
            encoding="utf-8",
        )
        config = {"llm_profiles": {"model-x": {"llm_service_class": "FakeBackend"}},
                  "default_llm_profile": "model-x"}
        services = {}
        services["llm"] = LLMRouter(config, services)
        reload_plugin = _reloader(monkeypatch, config=config, services=services)

        reload_plugin(str(path), "reload")

        assert services["model-x"].loaded
        assert messages == ["✓ Registered plugin: LLM backends"]
        path.unlink()
        reload_plugin(str(path), "unload")
        assert "model-x" not in services
    finally:
        unsub()


def test_reload_refreshes_runtime_commands(tmp_path, monkeypatch):
    """A command hot-load updates the runtime command snapshot."""
    path = _watched_dir(tmp_path, monkeypatch, "command") / "command_agent.py"
    path.write_text("x", encoding="utf-8")
    registry = _CommandRegistry()
    runtime = type("Runtime", (), {"commands": {}, "refreshes": 0})()
    runtime.refresh_session_specs = lambda: setattr(runtime, "refreshes", runtime.refreshes + 1)

    def fake_load(plugin_type, _path, **kwargs):
        command = type("AgentCommand", (), {"name": "agent", "_source_path": str(path.resolve())})()
        kwargs["command_registry"].register(command)
        return "agent", None

    monkeypatch.setattr("plugins.plugin_discovery.load_single_plugin", fake_load)

    _reloader(monkeypatch, command_registry=registry, runtime=runtime)(str(path), "reload")

    assert "agent" in registry._commands
    assert "agent" in runtime.commands
    assert runtime.refreshes == 1


def test_unload_refreshes_runtime_commands(tmp_path, monkeypatch):
    """A command hot-unload updates the runtime command snapshot."""
    path = _watched_dir(tmp_path, monkeypatch, "command") / "command_agent.py"
    path.write_text("x", encoding="utf-8")
    command = type("AgentCommand", (), {"name": "agent", "_source_path": str(path.resolve())})()
    registry = _CommandRegistry()
    registry.register(command)
    runtime = type("Runtime", (), {"commands": {"agent": command}, "refreshes": 0})()
    runtime.refresh_session_specs = lambda: setattr(runtime, "refreshes", runtime.refreshes + 1)
    monkeypatch.setattr("plugins.plugin_discovery.unload_plugin",
                        lambda *a, **k: registry.unregister("agent"))

    path.unlink()
    _reloader(monkeypatch, command_registry=registry, runtime=runtime)(str(path), "unload")

    assert "agent" not in registry._commands
    assert "agent" not in runtime.commands
    assert runtime.refreshes == 1


# ── the watcher (which paths, and when) ──────────────────────────────────
#
# All that is left of the service: a diff over mtimes. It holds no registries
# and touches no file, so these drive the real body through ``perform`` and
# assert on the ReloadPlugin requests it produced.


class _Recorder:
    """Captures ReloadPlugin calls instead of loading anything."""

    def __init__(self):
        self.calls = []

    def __call__(self, path, action):
        self.calls.append((Path(path).name, action))
        return {"ok": True}


def _watcher_context(directory, recorder, condemned=(), approve=True):
    """A context whose reload surface only records.

    ``approve`` matters: these test files are untrusted *and* legacy, so
    ``plugin_danger_tier`` grades them egress and the reload passes the approval
    gate. That is the real behaviour for an agent-authored plugin — see
    ``test_a_reload_the_user_denies_does_not_happen``."""
    return SimpleNamespace(
        db=None, services={}, runtime=None, session_key=None, user_id=1,
        root_dir=str(directory), approval_denial_reason="",
        approve_command=lambda _target, _why: approve,
        request_user_input=None, tool_registry=None, administer=None,
        config={"sandbox_trust_all": True,
                "sandbox_read_roots": [str(directory)],
                "_test_plugin_dirs": [str(directory)],
                "_test_condemned": list(condemned)})


@pytest.fixture
def watcher(monkeypatch):
    """The real watcher, with paths/inventory/reload pointed at the test dir."""
    from plugins.services.service_plugin_watcher import PluginWatcherService

    service = PluginWatcherService({})
    service._source_path = str(
        Path(__file__).resolve().parents[1] / "plugins" / "services" / "service_plugin_watcher.py")

    recorder = _Recorder()
    monkeypatch.setattr(
        "plugins.EffectsContract.EffectsContract._paths",
        lambda _self, ctx: {"plugin_dirs": ctx.config["_test_plugin_dirs"]})
    monkeypatch.setattr(
        "plugins.EffectsContract.EffectsContract._inventory",
        lambda _self, ctx: (lambda view: ctx.config["_test_condemned"]
                            if view == "quarantined_plugins" else []))
    monkeypatch.setattr(
        "plugins.EffectsContract.EffectsContract._reload_plugin",
        lambda _self, _ctx: recorder)
    service._recorder = recorder
    return service


def _tick(watcher, directory, condemned=(), approve=True):
    """Run one tick and return the (name, action) pairs it asked for."""
    before = len(watcher._recorder.calls)
    watcher.perform("tick", {}, _watcher_context(directory, watcher._recorder, condemned, approve))
    return watcher._recorder.calls[before:]


def test_the_first_tick_only_takes_a_baseline(tmp_path, watcher):
    """Discovery already loaded everything on disk at boot, so treating the
    existing tree as new would reload the whole thing a second after startup."""
    (tmp_path / "tool_demo.py").write_text("x", encoding="utf-8")

    assert _tick(watcher, tmp_path) == []


def test_a_new_file_loads_only_once_it_has_settled(tmp_path, watcher):
    """An editor's save is not atomic; importing a half-written file registers a
    plugin that never existed. The mtime has to repeat before it is loaded."""
    _tick(watcher, tmp_path)                       # baseline
    path = tmp_path / "tool_demo.py"
    path.write_text("x", encoding="utf-8")

    assert _tick(watcher, tmp_path) == [], "noticed, not yet settled"
    assert _tick(watcher, tmp_path) == [("tool_demo.py", "reload")]
    assert _tick(watcher, tmp_path) == [], "already loaded at this mtime"


def test_a_moving_mtime_keeps_waiting(tmp_path, watcher):
    import os

    _tick(watcher, tmp_path)
    path = tmp_path / "tool_demo.py"
    path.write_text("x", encoding="utf-8")
    _tick(watcher, tmp_path)
    os.utime(path, (0, 12345))                      # still being written

    assert _tick(watcher, tmp_path) == [], "mtime moved again -- wait another tick"
    assert _tick(watcher, tmp_path) == [("tool_demo.py", "reload")]


def test_an_edit_reloads(tmp_path, watcher):
    import os

    path = tmp_path / "tool_demo.py"
    path.write_text("x", encoding="utf-8")
    _tick(watcher, tmp_path)                        # baseline includes the file
    os.utime(path, (0, 999))

    _tick(watcher, tmp_path)
    assert _tick(watcher, tmp_path) == [("tool_demo.py", "reload")]


def test_a_deleted_file_unloads(tmp_path, watcher):
    path = tmp_path / "tool_demo.py"
    path.write_text("x", encoding="utf-8")
    _tick(watcher, tmp_path)
    path.unlink()

    assert _tick(watcher, tmp_path) == [("tool_demo.py", "unload")]


def test_services_load_before_tasks_in_one_batch(tmp_path, watcher):
    """A batch install must not leave tasks warning about missing services."""
    _tick(watcher, tmp_path)
    for name in ("task_b.py", "tool_c.py", "service_a.py"):
        (tmp_path / name).write_text("x", encoding="utf-8")
    _tick(watcher, tmp_path)

    assert [n for n, _a in _tick(watcher, tmp_path)] == [
        "service_a.py", "task_b.py", "tool_c.py"]


def test_a_reload_the_user_denies_does_not_happen(tmp_path, watcher):
    """Hot-reload is ``ReloadPlugin``, which is graded by the *target's*
    declarations and gated like any egress. A file the user refuses is not
    loaded — and the watcher does not retry it, because the mtime has been
    recorded either way."""
    _tick(watcher, tmp_path)
    (tmp_path / "tool_demo.py").write_text("x", encoding="utf-8")
    _tick(watcher, tmp_path, approve=False)

    assert _tick(watcher, tmp_path, approve=False) == [], "denied before it reached the loader"


def test_a_condemned_plugin_is_unloaded_without_a_file_change(tmp_path, watcher):
    """Quarantine used to need a bus subscription plus every kernel registry.
    Now the supervisor condemns, the watcher reads that, and the kernel unloads."""
    path = tmp_path / "tool_bad.py"
    path.write_text("x", encoding="utf-8")
    _tick(watcher, tmp_path)

    assert _tick(watcher, tmp_path, condemned=[str(path)]) == [("tool_bad.py", "unload")]
    assert _tick(watcher, tmp_path, condemned=[str(path)]) == [], "not unloaded twice"


def test_discovery_loads_sandbox_tree_relative_helpers(tmp_path, monkeypatch):
    """Verify sandbox_plugins tools can import family-local helpers relatively."""
    root = tmp_path / "sandbox_plugins"
    tools = root / "tools"
    helpers = tools / "helpers"
    helpers.mkdir(parents=True)
    (helpers / "answer.py").write_text('VALUE = "relative ok"\n', encoding="utf-8")
    (tools / "tool_relative.py").write_text(
        "from plugins.BaseTool import BaseTool, ToolResult\n"
        "from .helpers.answer import VALUE\n\n"
        "class RelativeTool(BaseTool):\n"
        "    name = 'relative_tool'\n"
        "    description = 'test'\n"
        "    parameters = {}\n"
        "    def run(self, context, **kwargs):\n"
        "        return ToolResult(llm_summary=VALUE)\n",
        encoding="utf-8",
    )
    _patch_tool_discovery(monkeypatch, (("sandbox", root, "sandbox_plugins", False),))
    registry = _ToolRegistry()

    plugin_discovery.discover_tools(tmp_path, registry, {}, reload=True)

    assert registry.tools["relative_tool"].run(None).llm_summary == "relative ok"


def test_discovery_precedence_prefers_sandbox_over_installed(tmp_path, monkeypatch):
    """Verify earlier roots win name collisions."""
    sandbox = tmp_path / "sandbox_plugins"
    installed = tmp_path / "installed_plugins"
    for root, label in ((sandbox, "sandbox"), (installed, "installed")):
        tools = root / "tools"
        tools.mkdir(parents=True)
        (tools / "tool_same.py").write_text(
            "from plugins.BaseTool import BaseTool\n\n"
            "class SameTool(BaseTool):\n"
            "    name = 'same_tool'\n"
            f"    description = '{label}'\n"
            "    parameters = {}\n",
            encoding="utf-8",
        )
    _patch_tool_discovery(
        monkeypatch,
        (("sandbox", sandbox, "sandbox_plugins", False), ("installed", installed, "installed_plugins", False)),
    )
    registry = _ToolRegistry()

    plugin_discovery.discover_tools(tmp_path, registry, {}, reload=True)

    assert registry.tools["same_tool"].description == "sandbox"


def test_load_single_tool_accepts_auto_register_false(tmp_path, monkeypatch):
    """Installing a tool that opts out of auto-registration is a no-op, not a
    failure: the file is on disk and something (e.g. plan mode) registers it on
    demand. Mirrors boot discovery, which silently skips such tools."""
    sandbox = tmp_path / "sandbox_plugins"
    tools = sandbox / "tools"
    tools.mkdir(parents=True)
    (tools / "tool_deferred.py").write_text(
        "from plugins.BaseTool import BaseTool, ToolResult\n\n"
        "class Deferred(BaseTool):\n"
        "    name = 'deferred'\n"
        "    description = 'test'\n"
        "    parameters = {}\n"
        "    auto_register = False\n"
        "    def run(self, context, **kwargs):\n"
        "        return ToolResult(data={})\n",
        encoding="utf-8",
    )
    _patch_tool_discovery(monkeypatch, (("sandbox", sandbox, "sandbox_plugins", False),))
    registry = _ToolRegistry()

    name, error = plugin_discovery._load_single_tool(tools / "tool_deferred.py", registry)

    assert error is None
    assert name == "deferred"
    assert registry.tools == {}  # opted out of the global registry


def test_load_single_tool_rejects_file_without_tool(tmp_path, monkeypatch):
    """A file with no BaseTool subclass at all is still a real failure."""
    sandbox = tmp_path / "sandbox_plugins"
    tools = sandbox / "tools"
    tools.mkdir(parents=True)
    (tools / "tool_empty.py").write_text("VALUE = 1\n", encoding="utf-8")
    _patch_tool_discovery(monkeypatch, (("sandbox", sandbox, "sandbox_plugins", False),))
    registry = _ToolRegistry()

    name, error = plugin_discovery._load_single_tool(tools / "tool_empty.py", registry)

    assert name is None
    assert "No BaseTool subclass found" in error


class _FakeHandler:
    """Fake handler."""
    cancelled = False

    def cancel_pending(self):
        """Cancel pending."""
        self.cancelled = True

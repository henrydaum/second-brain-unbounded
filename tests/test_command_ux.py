"""Tests for command-UX polish: parse-error propagation, /services toggles,
the Used-by map, and the session-conversation banner event.
"""

from types import SimpleNamespace

import state_machine  # noqa: F401  (import-order: break the runtime import cycle)

from events.event_bus import bus
from events.event_channels import SESSION_CONVERSATION_CHANGED
from pipeline.database import Database
from plugins.BaseFrontend import BaseFrontend, FrontendCapabilities
from plugins.commands.command_services import ServicesCommand
from runtime.conversation_runtime import ConversationRuntime


# ── Invalid one-shot command args are rendered, not swallowed ────────

class _CaptureFrontend(BaseFrontend):
    name = "capture"
    capabilities = FrontendCapabilities()

    def __init__(self):
        super().__init__()
        self.rendered = []

    def render_messages(self, _key, messages):
        self.rendered.extend(messages)

    def _current_approval_request(self, _key):
        return None


def test_invalid_command_args_render_a_message():
    fe = _CaptureFrontend()
    fe.commands = SimpleNamespace(parse_args=lambda *a, **k: (_ for _ in ()).throw(
        ValueError("job_name must be one of: fifa_world_cup_daily_update, add.")))

    args, handled = fe._parse_command_args("s", "schedule", "fifa world cup daily update")

    assert args is None
    assert handled is not None and not handled.ok
    assert any("Invalid arguments for `/schedule`" in m for m in fe.rendered)
    assert any("fifa_world_cup_daily_update" in m for m in fe.rendered)


def test_queued_ack_hook_suppresses_the_text_ack():
    from runtime.session import RuntimeResult

    fe = _CaptureFrontend()
    queued = RuntimeResult(messages=["Got it — I'll read that as soon as I finish this step."],
                           data={"queued": True})

    fe._render_result("s", queued)
    assert fe.rendered  # default hook: text ack renders

    fe.rendered.clear()
    fe.render_queued_ack = lambda _key: True  # reaction-capable frontend
    fe._render_result("s", queued)
    assert fe.rendered == []


# ── /services toggles ────────────────────────────────────────────────

class _ManagedService:
    loaded = False
    lifecycle = "managed"
    config_settings = [("Embed Model", "embed_model_name", "Model.", "x", {"type": "text"})]

    def load(self):
        self.loaded = True
        return True

    def unload(self):
        self.loaded = False


# /services runs on the effects contract, so these drive ``perform`` -- the
# kernel entry point -- rather than reaching into module helpers. The command no
# longer holds the service object: it names an action and the kernel's
# administration surface carries it out.

def _services_context(services, config, saved=None):
    """A context wired the way the command registry wires one."""
    from plugins.helpers.administration import build_administer

    context = SimpleNamespace(
        db=None, services=services, runtime=None, session_key="s1", user_id=1,
        root_dir=".", orchestrator=None, tool_registry=None, command_registry=None,
        approve_command=lambda *_a: True, approval_denial_reason="",
        request_user_input=None, principal="user",
        config={"sandbox_trust_all": True, **config})
    context.administer = build_administer(None, context.config, services, None, "s1")
    return context


def _run_services(context, **params):
    """Drive /services through its kernel entry point."""
    command = ServicesCommand()
    command._source_path = "plugins/commands/command_services.py"
    return command.perform(params, context)


def test_services_form_offers_toggles_labelled_by_current_state():
    svc = _ManagedService()
    context = _services_context({"embedder": svc}, {"autoload_services": []})

    command = ServicesCommand()
    command._source_path = "plugins/commands/command_services.py"
    steps = command.form_steps({"service_name": "embedder"}, context)

    action = next(s for s in steps if s.name == "action")
    assert action.enum[:2] == ["toggle_loaded", "toggle_autoload"]
    assert action.enum_labels[:2] == ["Load it", "Autoload on startup"]

    svc.loaded = True
    context.config["autoload_services"] = ["embedder"]
    steps = command.form_steps({"service_name": "embedder"}, context)
    action = next(s for s in steps if s.name == "action")
    assert action.enum_labels[:2] == ["Unload it", "Don't autoload on startup"]


def test_toggle_loaded_flips_service_state():
    svc = _ManagedService()
    context = _services_context({"embedder": svc}, {"autoload_services": []})

    out = _run_services(context, service_name="embedder", action="toggle_loaded")
    assert out == "Loaded service: embedder" and svc.loaded

    out = _run_services(context, service_name="embedder", action="toggle_loaded")
    assert out == "Unloaded service: embedder" and not svc.loaded


def test_toggle_autoload_updates_config(monkeypatch):
    saved = {}
    monkeypatch.setattr("config.config_manager.save", lambda cfg: saved.update(cfg))
    monkeypatch.setattr("config.config_manager.load", lambda: {"autoload_services": ["llm"]})
    context = _services_context({"embedder": _ManagedService()},
                                {"autoload_services": ["llm"]})

    out = _run_services(context, service_name="embedder", action="toggle_autoload")
    assert "now" in out
    assert saved["autoload_services"] == ["embedder", "llm"]

    context.config["autoload_services"] = ["embedder", "llm"]
    out = _run_services(context, service_name="embedder", action="toggle_autoload")
    assert "no longer" in out
    assert saved["autoload_services"] == ["llm"]


def test_an_agent_cannot_toggle_a_service():
    """The same command body, reached with the agent principal, is gated rather
    than allowed outright -- the whole point of the principal axis."""
    svc = _ManagedService()
    context = _services_context({"embedder": svc}, {"autoload_services": []})
    context.principal = "agent"
    context.approve_command = lambda *_a: False   # the human says no

    out = _run_services(context, service_name="embedder", action="toggle_loaded")

    assert not svc.loaded, "a denied approval must not load the service"
    assert "Could not" in out


# The "Edit <Setting>" quicklinks that /tools, /tasks, /services, and
# /frontends used to offer are gone in this pass. They worked by importing
# command_config's internals for each setting's current value -- which a
# sandboxed body cannot do. The pieces to rebuild them now exist (the settings
# inventory view for declarations, ReadConfig for values, and the setting_type /
# setting_prompt / format_value helpers in sandbox_kit), so restoring the
# shortcut is a small addition rather than a redesign. /config edits every
# setting in the meantime.


def test_setting_plugin_names_accumulate_across_declarers():
    from plugins import plugin_discovery as pd

    class A:
        name = "tool_a"
        config_settings = [("Shared", "shared_key_ux_test", "d", 1, {"type": "text"})]

    class B:
        name = "svc_b"
        config_settings = [("Shared", "shared_key_ux_test", "d", 1, {"type": "text"})]

    pd._collect_config_settings(A(), plugin_type="tool")
    pd._collect_config_settings(B(), service_names=["svc_b"], plugin_type="service")
    try:
        assert pd.get_setting_plugin_names("shared_key_ux_test") == ["svc_b", "tool_a"]
    finally:
        pd._setting_to_plugins.pop("shared_key_ux_test", None)
        pd._setting_to_services.pop("shared_key_ux_test", None)


# ── Session conversation banner event ────────────────────────────────

def test_load_conversation_emits_session_conversation_changed(tmp_path):
    db = Database(str(tmp_path / "banner.db"))
    cid = db.create_conversation("FIFA Briefings")
    rt = ConversationRuntime(db=db, services={}, config={})
    seen = []
    unsub = bus.subscribe(SESSION_CONVERSATION_CHANGED, seen.append)
    try:
        rt.load_conversation("s", cid)
    finally:
        unsub()

    assert any(p["session_key"] == "s" and p["conversation_id"] == cid
               and p["title"] == "FIFA Briefings" for p in seen)

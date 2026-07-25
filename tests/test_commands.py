"""Tests for the kernel slash commands.

Only the REPL/introspection commands ship in the kernel. These exercise the
two with non-trivial logic: ``/llm`` (profile management form + handler) and
``/debug`` (live state-machine snapshot + recent log tail). Both stub their
context dependencies.
"""

from types import SimpleNamespace

from plugins.commands import command_debug
from plugins.commands.command_frontends import FrontendsCommand
from plugins.commands.command_agent import AgentCommand
from plugins.commands.command_debug import DebugCommand
from plugins.commands.command_llm import LlmCommand
from state_machine.conversation import ConversationState, Participant


# ── /llm ─────────────────────────────────────────────────────────────
#
# /llm runs on the effects contract, so these drive it through ``perform`` /
# ``form_steps``. It no longer calls the live router: writing llm_profiles is
# what resyncs it, kernel-side, the same way writing the sync directories
# rescans the watcher. So the fixtures patch the config store rather than
# stubbing an ``add_llm``/``remove_llm`` pair.

def _llm_context(config, monkeypatch, saved):
    """A context wired the way the command registry wires one."""
    from plugins.helpers.administration import build_administer

    monkeypatch.setattr("config.config_manager.save", lambda cfg: None)
    monkeypatch.setattr("config.config_manager.load", lambda: dict(config))
    monkeypatch.setattr("config.config_manager.load_plugin_config", lambda: {"kept": True})
    monkeypatch.setattr("config.config_manager.save_plugin_config",
                        lambda values: saved.update(values))
    # service_llm declares both keys, so in production they persist to
    # plugin_config.json as well as config.json. Discovery finds no plugins in a
    # bare test process, so say so explicitly rather than let the assertions
    # quietly check the wrong file.
    monkeypatch.setattr(
        "plugins.plugin_discovery.get_plugin_settings",
        lambda: [("LLM Profiles", "llm_profiles", "", {}, {"type": "json_dict"}),
                 ("Default LLM Profile", "default_llm_profile", "", "", {"type": "text"})])

    runtime = SimpleNamespace(config=dict(config), refresh_session_specs=lambda: None)
    context = SimpleNamespace(
        db=None, services={}, runtime=runtime, session_key="s1", user_id=1,
        root_dir=".", orchestrator=None, tool_registry=None, command_registry=None,
        approve_command=lambda *_a: True, approval_denial_reason="",
        request_user_input=None, principal="user",
        config={"sandbox_trust_all": True, **config})
    context.administer = build_administer(None, context.config, {}, runtime, "s1",
                                          context=context)
    return context


def _llm(context, **params):
    """Drive /llm through its kernel entry point."""
    command = LlmCommand()
    command._source_path = "plugins/commands/command_llm.py"
    return command.perform(params, context)


def _llm_form(context, **params):
    """The form steps /llm offers."""
    command = LlmCommand()
    command._source_path = "plugins/commands/command_llm.py"
    return command.form_steps(params, context)


def test_llm_command_can_set_default(monkeypatch):
    saved = {}
    context = _llm_context({"llm_profiles": {"a": {}, "b": {}},
                            "default_llm_profile": "a"}, monkeypatch, saved)

    steps = _llm_form(context, model_name="b")
    result = _llm(context, model_name="b", action="set_default")

    assert steps[0].prompt.splitlines() == ["Select an LLM profile, or add a new one.",
                                            "Default: a"]
    assert steps[1].enum == ["edit", "set_default", "remove"]
    assert steps[1].enum_labels == ["Edit", "Set default", "Remove"]
    assert result == "Default LLM profile set to: b"
    assert saved["default_llm_profile"] == "b"


def test_llm_command_set_default_writes_through_to_runtime_config(monkeypatch):
    """The write-through the plugin used to perform by hand is now the kernel's."""
    saved = {}
    context = _llm_context({"llm_profiles": {"a": {}, "b": {}},
                            "default_llm_profile": ""}, monkeypatch, saved)

    result = _llm(context, model_name="b", action="set_default")

    assert result == "Default LLM profile set to: b"
    assert saved["kept"] is True          # unrelated plugin config preserved
    assert saved["default_llm_profile"] == "b"
    assert context.runtime.config["default_llm_profile"] == "b"


def test_llm_command_add_stores_declared_capabilities(monkeypatch):
    saved = {}
    context = _llm_context({"llm_profiles": {}, "default_llm_profile": ""},
                           monkeypatch, saved)

    steps = _llm_form(context, model_name="add")
    result = _llm(context, model_name="add", new_model_name="openai/gpt-4o",
                  llm_service_class="LiteLLMService", llm_endpoint="",
                  llm_api_key="OPENAI_API_KEY", llm_context_size=0,
                  llm_capability_image=True, llm_capability_audio=False)

    profile = saved["llm_profiles"]["openai/gpt-4o"]
    assert [s.name for s in steps][-3:] == ["llm_capability_image",
                                            "llm_capability_audio",
                                            "llm_capability_video"]
    assert result == "Added LLM profile: openai/gpt-4o"
    assert saved["default_llm_profile"] == "openai/gpt-4o"   # first profile wins
    assert profile["llm_capabilities"] == {"image": True, "audio": False}
    assert not any(k.startswith("llm_capability_") for k in profile)


def test_llm_command_can_rename_profile(monkeypatch):
    saved = {}
    context = _llm_context(
        {"llm_profiles": {"bad": {"llm_endpoint": "https://api.atlascloud.ai/v1"}},
         "default_llm_profile": "bad"}, monkeypatch, saved)

    steps = _llm_form(context, model_name="bad", action="edit")
    result = _llm(context, model_name="bad", action="edit",
                  field="llm_model_name", value="deepseek-ai/deepseek-v4-pro")

    assert "llm_model_name" in next(s.enum for s in steps if s.name == "field")
    assert result == "Updated LLM profile: deepseek-ai/deepseek-v4-pro"
    assert "bad" not in saved["llm_profiles"]
    assert "deepseek-ai/deepseek-v4-pro" in saved["llm_profiles"]
    # renaming the default carries the default with it
    assert saved["default_llm_profile"] == "deepseek-ai/deepseek-v4-pro"


def test_llm_command_remove_default_selects_next_profile(monkeypatch):
    saved = {}
    context = _llm_context({"llm_profiles": {"a": {}, "b": {}, "c": {}},
                            "default_llm_profile": "b"}, monkeypatch, saved)

    result = _llm(context, model_name="b", action="remove")

    assert result == "Removed LLM profile: b"
    assert saved["default_llm_profile"] == "c"


def test_llm_command_add_does_not_replace_existing_default(monkeypatch):
    saved = {}
    context = _llm_context({"llm_profiles": {"a": {}}, "default_llm_profile": "a"},
                           monkeypatch, saved)

    result = _llm(context, model_name="add", new_model_name="b")

    assert result == "Added LLM profile: b"
    assert "b" in saved["llm_profiles"]
    # The default is left strictly alone -- not rewritten to its current value.
    # The old shape resaved every key on every edit, so "unchanged" and "not
    # written" were indistinguishable; now only what actually changed is written.
    assert "default_llm_profile" not in saved
    assert context.config["default_llm_profile"] == "a"


def test_llm_command_remove_last_default_blanks_default(monkeypatch):
    saved = {}
    context = _llm_context({"llm_profiles": {"a": {}}, "default_llm_profile": "a"},
                           monkeypatch, saved)

    result = _llm(context, model_name="a", action="remove")

    assert result == "Removed LLM profile: a"
    assert saved["default_llm_profile"] == ""


# ── /agent ───────────────────────────────────────────────────────────

def test_agent_command_can_rename_profile(monkeypatch):
    """A rename touches three places, and the split of *who* touches them is the
    point of the conversion: the profile dict is a global WriteConfig, the active
    selection is a user-scoped one, and the stale references on live sessions are
    fixed by the kernel through SessionAction -- a plugin has no business walking
    the session table."""
    from plugins.helpers.administration import build_administer

    saved = {}
    monkeypatch.setattr("config.config_manager.save", lambda cfg: saved.update(cfg))
    monkeypatch.setattr("config.config_manager.load",
                        lambda: {"agent_profiles": {"builder": {"llm": "default"}}})

    session = SimpleNamespace(active_agent_profile="builder", profile_override="builder")
    runtime = SimpleNamespace(sessions={"chat": session},
                              refresh_session_specs=lambda: None,
                              set_agent_profile=lambda _k, _n: True)
    context = SimpleNamespace(
        config={"agent_profiles": {"builder": {"llm": "default"}},
                "active_agent_profile": "builder", "sandbox_trust_all": True},
        runtime=runtime, session_key="chat", db=None, user_id=1, services={},
        root_dir=".", orchestrator=None, tool_registry=None, command_registry=None,
        approve_command=lambda *_a: True, approval_denial_reason="",
        request_user_input=None, principal="user")
    context.administer = build_administer(None, context.config, {}, runtime, "chat",
                                          context=context)

    command = AgentCommand()
    command._source_path = "plugins/commands/command_agent.py"
    steps = command.form_steps({"profile_name": "builder", "action": "edit"}, context)
    result = command.perform({"profile_name": "builder", "action": "edit",
                              "field": "agent_profile_name", "value": "writer"}, context)

    assert "agent_profile_name" in next(s.enum for s in steps if s.name == "field")
    assert result == "Updated agent profile: writer"
    assert "builder" not in saved["agent_profiles"]
    assert "writer" in saved["agent_profiles"]
    # the kernel fixed the live session's stale references
    assert session.active_agent_profile == "writer"
    assert session.profile_override == "writer"


# ── /frontends ───────────────────────────────────────────────────────

def test_frontends_form_uses_runtime_cache_without_discovery(monkeypatch):
    def boom(*_args, **_kwargs):
        raise AssertionError("frontend discovery should not run while rendering form hints")

    monkeypatch.setattr("plugins.plugin_discovery.discover_frontends", boom)
    manager = SimpleNamespace(available_frontends={"repl", "telegram"}, adapters={"repl": object()})
    runtime = SimpleNamespace(frontend_manager=manager)
    context = SimpleNamespace(
        config={"enabled_frontends": ["repl"], "frontend_profiles": {},
                "sandbox_trust_all": True},
        runtime=runtime, db=None, services={}, session_key="s1", user_id=1,
        root_dir=".", orchestrator=None, tool_registry=None, command_registry=None,
        approve_command=None, approval_denial_reason="", request_user_input=None,
        administer=None, principal="user")

    command = FrontendsCommand()
    command._source_path = "plugins/commands/command_frontends.py"
    steps = command.form_steps({}, context)

    assert steps[0].enum == ["repl", "telegram"]


# ── /debug ───────────────────────────────────────────────────────────

# /debug runs on the effects contract, so it is driven through ``perform`` --
# the kernel entry point -- rather than by calling ``run`` directly. It no longer
# imports DATA_DIR either: the log's location arrives as ReadContext("paths"),
# which is why these fixtures supply a path map instead of monkeypatching a
# module global.

def _session_context(tmp_path, cs=None, **session_attrs):
    """A context for /debug: a real log file, and the paths view pointed at it."""
    (tmp_path / "app.log").write_text(
        "01:00PM | Main         | INFO  | ok\n"
        "01:01PM | Discovery    | WARNING | Plugin registration failed: demo\n"
        "01:02PM | Main         | ERROR | Auto-load failed for 'llm': boom\n",
        encoding="utf-8",
    )
    sessions = {"chat": SimpleNamespace(cs=cs, **session_attrs)} if cs is not None else {}
    return SimpleNamespace(
        runtime=SimpleNamespace(sessions=sessions), session_key="chat", services={},
        db=None, config={"sandbox_trust_all": True, "sandbox_read_roots": [str(tmp_path)]},
        root_dir=str(tmp_path), user_id=1, orchestrator=None, tool_registry=None,
        command_registry=None, approve_command=None, approval_denial_reason="",
        request_user_input=None, administer=None, principal="user")


def _debug(context):
    """Drive /debug through its kernel entry point."""
    command = DebugCommand()
    command._source_path = "plugins/commands/command_debug.py"
    return command.perform({}, context)


def test_debug_reports_state_machine_snapshot_and_log_tail(tmp_path, monkeypatch):
    cs = ConversationState([Participant("user", "user"), Participant("agent", "agent")])
    context = _session_context(tmp_path, cs)
    context.services["sample"] = SimpleNamespace(debug_flags=lambda _session: ["sample extension"])
    monkeypatch.setattr("paths.DATA_DIR", tmp_path, raising=False)

    out = _debug(context)

    assert "**Conversation state**" in out
    assert "Turn: user (user)" in out
    assert f"Phase: {cs.phase}" in out
    assert "Participants: user(user), agent(agent)" in out
    assert "Session: sample extension" in out
    # The valuable part of the old /doctor: recent warnings/errors.
    assert "**Recent log warnings/errors**" in out
    assert "Plugin registration failed: demo" in out
    assert "Auto-load failed for 'llm': boom" in out
    assert "INFO  | ok" not in out  # info lines are filtered out


def test_debug_handles_no_active_session(tmp_path, monkeypatch):
    context = _session_context(tmp_path)
    monkeypatch.setattr("paths.DATA_DIR", tmp_path, raising=False)

    out = _debug(context)

    assert "(no active session)" in out


# ── agent_prompt contributions ───────────────────────────────────────

def test_kernel_commands_contribute_agent_prompt_guidance():
    """The /llm, /agent, and /packages commands carry the SB-specific facts a
    model cannot infer: mid-conversation model/profile switches and hot-reload
    catalog changes."""
    from plugins.commands.command_packages import PackagesCommand

    assert "different model" in LlmCommand().agent_prompt_for(None)
    assert "profile" in AgentCommand().agent_prompt_for(None)
    assert "next turn" in PackagesCommand().agent_prompt_for(None)

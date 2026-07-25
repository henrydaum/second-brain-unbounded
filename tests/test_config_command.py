"""Tests for the /config drill-down gate: settings browse by category (kernel /
plugin / user / all), and plugin settings drill down a second level by owning
plugin. One-shot ``/config <setting>`` keeps working because the category (and
plugin_name) steps are optional enums the parser can skip.

/config runs on the effects contract, so these drive it through ``perform`` and
``form_steps`` — its kernel entry points — rather than calling module helpers.
The plugin-settings lookup now lives in ``plugins.helpers.inventory`` (the
settings *catalog* is an ungated read; the *values* go through the
principal-graded ReadConfig), so that is what the fixtures patch.
"""

from types import SimpleNamespace

import pytest

import state_machine  # noqa: F401  (import-order: break the runtime import cycle)

from plugins.commands import command_config as cc
from plugins.commands.command_config import ConfigCommand
from plugins.frontends.helpers.command_registry import parse_command_line

_PLUGIN_SETTINGS = [
    ("Brave Search API Key", "brave_search_api_key", "API key.", "", {"type": "text"}),
    ("Title Delay (minutes)", "title_delay_minutes", "Delay.", 10,
     {"type": "slider", "range": (0, 60, 60), "is_float": False}),
]

# Owning-plugin map for the plugin settings above; title_delay is intentionally
# shared by two plugins to exercise the double-listing + shared-note paths.
_OWNERS = {
    "brave_search_api_key": ["tool_web_search"],
    "title_delay_minutes": ["service_llm", "service_titler"],
}


@pytest.fixture
def plugins(monkeypatch):
    """Patch plugin-setting discovery where the inventory reads it."""
    monkeypatch.setattr("plugins.plugin_discovery.get_plugin_settings",
                        lambda: _PLUGIN_SETTINGS)
    monkeypatch.setattr("plugins.plugin_discovery.get_plugin_setting_scope",
                        lambda key: "global")
    monkeypatch.setattr("plugins.plugin_discovery.get_setting_plugin_names",
                        lambda key: _OWNERS.get(key, []))


def _ctx(**overrides):
    """A context wired the way the command registry wires one."""
    from plugins.helpers.administration import build_administer

    base = dict(
        db=None, services={}, runtime=None, session_key="s1", user_id=1,
        root_dir=".", orchestrator=None, tool_registry=None, command_registry=None,
        approve_command=lambda *_a: True, approval_denial_reason="",
        request_user_input=None, principal="user",
        config={"sandbox_trust_all": True})
    base.update(overrides)
    context = SimpleNamespace(**base)
    context.administer = build_administer(context.db, context.config, {}, None, "s1",
                                          context=context)
    return context


def _command():
    """A /config instance ready to drive through its entry points."""
    command = ConfigCommand()
    command._source_path = "plugins/commands/command_config.py"
    return command


def _form(args):
    """The form steps /config offers for these arguments."""
    return _command().form_steps(args, _ctx())


def _run(args):
    """/config's markdown output for these arguments."""
    return _command().perform(args, _ctx())


def _catalog():
    """The settings catalog as the command sees it."""
    from plugins.helpers.inventory import _settings_catalog

    return _settings_catalog()


def _keys():
    """Every settable key."""
    return {s["key"] for s in _catalog()}


def test_categories_partition_all_settings(plugins):
    catalog = _catalog()
    by_key = {s["key"]: s for s in catalog}

    assert by_key["stream_responses"]["category"] == "kernel"
    assert by_key["brave_search_api_key"]["category"] == "plugin"
    assert by_key["skip_permissions"]["category"] == "user"  # user-scoped core setting

    counts = {name: len([s for s in catalog if s["category"] == name])
              for name in cc._REAL_CATEGORIES}
    assert counts["plugin"] == 2
    # The three real categories partition every setting.
    assert sum(counts.values()) == len(catalog)


def test_plugin_groups_group_by_owner(plugins):
    groups = cc._by_owner(_catalog())

    assert [s["key"] for s in groups["tool_web_search"]] == ["brave_search_api_key"]
    # Shared setting is listed under each owning plugin.
    assert "title_delay_minutes" in [s["key"] for s in groups["service_llm"]]
    assert "title_delay_minutes" in [s["key"] for s in groups["service_titler"]]


def test_form_gates_settings_by_category(plugins):
    steps = _form({})
    assert steps[0].name == "category"
    # Required: the category gate is the always-shown default (four buttons) and,
    # being required, never offers a redundant "skip" (skip == "all").
    assert steps[0].required is True
    assert steps[0].enum == ["kernel", "plugin", "user", "all"]
    assert steps[0].enum_labels == ["Kernel Settings", "Plugin Settings",
                                    "User Settings", "All Settings"]
    assert steps[1].name == "setting_name"
    assert set(steps[1].enum) == _keys()  # unfiltered until chosen

    steps = _form({"category": "user"})
    name_step = next(s for s in steps if s.name == "setting_name")
    assert "skip_permissions" in name_step.enum
    assert "stream_responses" not in name_step.enum

    steps = _form({"category": "all"})
    assert set(steps[-1].enum) == _keys()


def test_form_plugin_category_drills_into_plugin_level(plugins):
    # Choosing plugin inserts an optional plugin_name enum before setting_name.
    steps = _form({"category": "plugin"})
    assert [s.name for s in steps][:2] == ["category", "plugin_name"]
    assert steps[1].required is False
    assert set(steps[1].enum) == {"tool_web_search", "service_llm", "service_titler"}

    # With a plugin chosen, setting_name is filtered to that plugin's settings.
    steps = _form({"category": "plugin", "plugin_name": "service_llm"})
    name_step = next(s for s in steps if s.name == "setting_name")
    assert name_step.enum == ["title_delay_minutes"]


def test_direct_setting_args_skip_the_category_gate(plugins):
    steps = _form({"setting_name": "stream_responses"})

    assert [s.name for s in steps][:2] == ["setting_name", "action"]


def test_one_shot_requires_category(plugins):
    # The legacy `/config <setting>` fall-through is gone: a setting is always
    # reached through its category. `/config kernel stream_responses` works...
    command = _command()
    context = _ctx()

    args = parse_command_line("kernel stream_responses",
                              lambda a, c: command.form_steps(a, context))

    assert args["category"] == "kernel"
    assert args["setting_name"] == "stream_responses"


def test_one_shot_all_category_reaches_any_setting(plugins):
    # ...and `all` is the explicit escape hatch for any setting, flat.
    command = _command()
    context = _ctx()

    args = parse_command_line("all max_workers edit 6",
                              lambda a, c: command.form_steps(a, context))

    assert args["category"] == "all"
    assert args["setting_name"] == "max_workers"
    assert args["action"] == "edit"
    assert args["value"] == 6


def test_one_shot_category_setting_skips_plugin_level(plugins):
    # `/config plugin <setting>` (no plugin name) still resolves: plugin_name is
    # an optional enum the parser skips when the token isn't a known plugin.
    command = _command()
    context = _ctx()

    args = parse_command_line("plugin title_delay_minutes",
                              lambda a, c: command.form_steps(a, context))

    assert args["category"] == "plugin"
    assert args.get("plugin_name") is None
    assert args["setting_name"] == "title_delay_minutes"


def test_one_shot_plugin_drilldown_parses(plugins):
    # The canonical plugin path: `/config plugin <plugin> <setting> edit <val>`.
    command = _command()
    context = _ctx()

    args = parse_command_line("plugin service_llm title_delay_minutes edit 25",
                              lambda a, c: command.form_steps(a, context))

    assert args["category"] == "plugin"
    assert args["plugin_name"] == "service_llm"
    assert args["setting_name"] == "title_delay_minutes"
    assert args["action"] == "edit"
    assert args["value"] == 25


def test_list_groups_by_category(plugins):
    out = _run({})
    assert "Kernel Settings (config.json):" in out
    assert "Plugin Settings (plugin_config.json):" in out
    assert "User Settings (per-user):" in out

    # Plugin category with no plugin chosen groups by owning plugin.
    out = _run({"category": "plugin"})
    assert "Kernel Settings" not in out
    assert "tool_web_search:" in out
    assert "service_llm:" in out
    assert "brave_search_api_key" in out

    # Drilled into one plugin.
    out = _run({"category": "plugin", "plugin_name": "tool_web_search"})
    assert "brave_search_api_key" in out
    assert "title_delay_minutes" not in out


def test_describe_notes_shared_settings(plugins):
    out = _run({"setting_name": "title_delay_minutes"})
    assert "Shared setting" in out
    assert "service_titler" in out

    out = _run({"setting_name": "brave_search_api_key"})
    assert "Shared setting" not in out


def test_the_catalog_never_carries_values(plugins):
    """The split that keeps /config honest.

    A setting's declaration is public and rides an ungated inventory read; its
    value may be an API key and must go through ReadConfig, which is
    principal-graded. If a value ever appeared in the catalog it would reach any
    plugin that can call ReadContext -- routing around that gate entirely."""
    assert all("value" not in setting for setting in _catalog())

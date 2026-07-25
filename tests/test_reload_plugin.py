"""Registry mutation as a mediated verb — retiring the "mutates registries" exception.

Loading a plugin changes what the kernel *is*, which is why it looked like it
had to be trusted. But the conclusion was backwards: today `plugin_watcher`
mutates registries directly, with no ledger row and no gate. Routing it through
a request makes it *more* mediated than the in-process version, not less.

Egress tier, on the strict reading of the deferred-execution rule: loading a
plugin executes code, which is the one thing a write must never become, and you
cannot un-run a module's import side effects.
"""

from __future__ import annotations

import pytest

from effects.interpreter import EffectContext, Interpreter
from effects.vocabulary import ReloadPlugin


def _interp(tmp_path, *, loader=None, gate=None, declared=("reload_plugin",)):
    ctx = EffectContext(
        read_roots=[tmp_path], write_roots=[tmp_path], tool_name="watcher",
        reload_plugin=loader,
        egress_gate=gate or (lambda r: (True, "")),
    )
    return Interpreter(ctx, list(declared)), ctx


def test_reloading_a_plugin_goes_through_the_loader(tmp_path):
    """The verb reaches the kernel's loader — the plugin never imports anything."""
    seen = []
    target = tmp_path / "tool_x.py"
    target.write_text("# a plugin", encoding="utf-8")
    interp, _ = _interp(tmp_path, loader=lambda p, a: seen.append((p, a)) or {"loaded": True})

    result = interp.fulfill(ReloadPlugin(path=str(target)))

    assert result.ok
    assert result.value == {"loaded": True}
    assert seen and seen[0][1] == "reload"


def test_unload_is_the_same_verb_with_a_different_action(tmp_path):
    """Quarantining a misbehaving plugin is registry mutation too."""
    seen = []
    target = tmp_path / "tool_x.py"
    target.write_text("# a plugin", encoding="utf-8")
    interp, _ = _interp(tmp_path, loader=lambda p, a: seen.append((p, a)) or {"unloaded": True})

    interp.fulfill(ReloadPlugin(path=str(target), action="unload"))

    assert seen[0][1] == "unload"


def test_reload_is_gated(tmp_path):
    """Egress tier means it passes the approval surface like any irreversible
    act — a denial is a normal outcome, not a crash."""
    called = []
    target = tmp_path / "tool_x.py"
    target.write_text("# a plugin", encoding="utf-8")
    interp, _ = _interp(
        tmp_path,
        loader=lambda p, a: called.append(p),
        gate=lambda r: (False, "user said no"))

    result = interp.fulfill(ReloadPlugin(path=str(target)))

    assert not result.ok
    assert result.denied
    assert called == [], "a denied reload still executed"


def test_reload_is_root_confined(tmp_path):
    """A plugin cannot ask the kernel to load code from anywhere on disk."""
    outside = tmp_path.parent / "evil_plugin.py"
    outside.write_text("# not in the roots", encoding="utf-8")
    called = []
    interp, _ = _interp(tmp_path, loader=lambda p, a: called.append(p))

    result = interp.fulfill(ReloadPlugin(path=str(outside)))

    assert not result.ok
    assert "outside the allowed" in result.error
    assert called == []


def test_reload_must_be_declared(tmp_path):
    """No special case: an undeclared reload is a hard reject."""
    from effects.declarations import UndeclaredRequestError

    target = tmp_path / "tool_x.py"
    target.write_text("# a plugin", encoding="utf-8")
    interp, _ = _interp(tmp_path, loader=lambda p, a: None, declared=())

    with pytest.raises(UndeclaredRequestError):
        interp.fulfill(ReloadPlugin(path=str(target)))


def test_declaring_reload_makes_a_plugin_egress_tier():
    """A hot-reloader is dangerous, and its derived tier says so without the
    author asserting anything."""
    from effects.declarations import derive_tier

    assert derive_tier(["reload_plugin"]) == "egress"
    assert derive_tier(["read_file", "reload_plugin"]) == "egress"


def test_a_missing_loader_fails_rather_than_silently_doing_nothing(tmp_path):
    """If registry mutation is unavailable the plugin learns that, instead of
    believing its reload succeeded."""
    target = tmp_path / "tool_x.py"
    target.write_text("# a plugin", encoding="utf-8")
    interp, _ = _interp(tmp_path, loader=None)

    result = interp.fulfill(ReloadPlugin(path=str(target)))

    assert not result.ok
    assert "no plugin loader" in result.error


def test_the_reload_is_ledger_recorded(tmp_path):
    """Registry mutation becomes auditable, which the in-process version never
    was — this is the point of the whole exercise."""
    rows = []

    class _Db:
        def record_action(self, **kw):
            rows.append(kw)

    target = tmp_path / "tool_x.py"
    target.write_text("# a plugin", encoding="utf-8")
    ctx = EffectContext(
        read_roots=[tmp_path], write_roots=[tmp_path], tool_name="watcher", db=_Db(),
        reload_plugin=lambda p, a: {"loaded": True}, egress_gate=lambda r: (True, ""))

    Interpreter(ctx, ["reload_plugin"]).fulfill(ReloadPlugin(path=str(target)))

    assert rows and rows[0]["action_type"] == "reload_plugin"
    assert rows[0]["data"]["tier"] == "egress"

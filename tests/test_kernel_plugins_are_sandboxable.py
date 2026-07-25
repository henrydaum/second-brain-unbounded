"""A plugin on the effects contract must actually be able to run sandboxed.

"Converted" and "runs untrusted" are different claims, and only the first one was
ever being checked. Every kernel plugin is built-in, so ``is_trusted`` says yes
and every one of them runs in-process — which means a converted plugin can import
whatever it likes and nothing ever notices. Two did:

- ``service_compactor`` — the *exemplar*, the plugin cited as proof that a real
  kernel service can cross the boundary — imported ``logging`` at module scope.
  The gate refuses it, correctly (``logging.FileHandler`` opens files).
- ``command_commands`` reached ``plugins.frontends.helpers.formatters``
  absolutely, when ``sandbox_kit`` exposes the same ``md_table``.

Neither ever failed. Both would have failed instantly the moment anyone shipped
the same code from the store tree, where provenance is not built-in.

So this test asks the question the contract flag does not: given this plugin's
closure, is there anything in it the sandbox would refuse? The exceptions are
listed by name with the work that will clear them, so "add it to the list" stays
a deliberate act rather than a quiet one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sandbox.closure import build_closure

ROOT = Path(__file__).resolve().parents[1]

# Kernel plugins that are on the effects contract but cannot yet run untrusted,
# each with the work that will clear it. This list should only ever shrink.
NOT_YET_SANDBOXABLE: dict[str, str] = {}

# Plugins still on the legacy contract are out of scope here — they are covered
# by tests/test_trusted_exception_is_closed.py, which tracks the conversion
# itself. This file only asks whether a *converted* plugin is honest.


def _kernel_plugins() -> dict[str, Path]:
    """Every plugin entry point shipped in the kernel tree."""
    out = {}
    for family in ("commands", "services", "tools", "tasks", "frontends"):
        directory = ROOT / "plugins" / family
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*_*.py")):
            if path.name.startswith("_"):
                continue
            out[path.stem] = path
    return out


def _on_contract(path: Path) -> bool:
    """Whether this file opts into the effects contract."""
    return 'contract = "effects"' in path.read_text(encoding="utf-8")


CONVERTED = sorted(stem for stem, path in _kernel_plugins().items() if _on_contract(path))


def test_there_are_converted_plugins_to_check():
    """Guards against the parametrization silently collecting nothing."""
    assert CONVERTED, "no kernel plugin is on the effects contract; the sweep is vacuous"


@pytest.mark.parametrize("stem", CONVERTED)
def test_a_converted_kernel_plugin_can_actually_run_sandboxed(stem):
    """Its whole closure — helpers included — must pass the import gate."""
    if stem in NOT_YET_SANDBOXABLE:
        pytest.xfail(f"{stem}: {NOT_YET_SANDBOXABLE[stem]}")

    path = _kernel_plugins()[stem]
    closure = build_closure(path)

    assert not closure.needs_trust, (
        f"{stem} declares contract = \"effects\" but its closure imports "
        f"{closure.outside_names()}, which the sandbox gate refuses.\n"
        f"Wanted by: "
        + "; ".join(f"{name} <- {', '.join(w or '(the plugin)' for w in who)}"
                    for name, who in sorted(closure.outside.items()))
        + "\nIt runs today only because built-in provenance makes it trusted. "
          "Ship the same file from the store and it stops working.\n"
          "Either remove the import (sandbox_kit usually has the equivalent), or "
          "add it to NOT_YET_SANDBOXABLE with the work that will clear it."
    )


@pytest.mark.parametrize("stem", CONVERTED)
def test_a_converted_plugin_declares_no_unreadable_or_missing_helpers(stem):
    """A helper that does not resolve is a broken install rather than a risk, but
    in the kernel tree it is always a bug — nothing here is half-installed."""
    closure = build_closure(_kernel_plugins()[stem])

    assert not closure.missing, f"{stem} imports helpers that do not exist: {closure.missing}"
    assert not closure.unreadable, f"{stem} has unparseable files: {closure.unreadable}"


def test_the_exception_list_only_names_real_plugins():
    """A stale entry hides that the exception could have been retired."""
    unknown = sorted(set(NOT_YET_SANDBOXABLE) - set(_kernel_plugins()))
    assert not unknown, f"NOT_YET_SANDBOXABLE names plugins that no longer exist: {unknown}"


def test_the_compactor_is_genuinely_sandboxable():
    """Called out on its own because it is the plugin the design *cites* as proof
    that a real kernel service can cross the boundary. If this one cannot run
    untrusted, the claim it is making is not true."""
    closure = build_closure(_kernel_plugins()["service_compactor"])

    assert not closure.needs_trust, (
        f"the exemplar service reaches {closure.outside_names()} outside the gate")

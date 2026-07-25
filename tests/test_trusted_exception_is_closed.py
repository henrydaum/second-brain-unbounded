"""The always-trusted exception must not grow quietly.

The design's promise is that a plugin's security level is *not* a per-plugin
judgement: almost everything is sandboxable, and the exceptions fit on one page.
That promise decays silently unless something counts them, because each new
exception looks locally reasonable.

So this test pins the list. Adding a plugin to it requires citing one of the five
capabilities in "What requires the always-trusted exception"
(effects/PRIMITIVES.md) — and editing this file, deliberately.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Kernel plugins that legitimately cannot use the effects contract, each mapped
# to the numbered capability that forces it. An entry that cannot cite one is a
# bug, not an exception.
TRUSTED_EXCEPTION = {
    "service_llm": "1 (live sockets/keys), 4 (on_delta streaming callbacks)",
    "service_plugin_watcher": "2 (watchdog Observer thread), 3 (mutates registries)",
    "service_parser": "5 (registry of live parser functions)",
}

# The five capabilities, kept here so the citation strings stay meaningful and a
# reader of this test does not have to open the doc to know what they mean.
CAPABILITIES = {
    1: "hold a live handle across calls",
    2: "own a thread or event loop",
    3: "mutate kernel registries",
    4: "be called back synchronously mid-operation",
    5: "hand the kernel a live callable it will execute",
}


def _kernel_services() -> dict[str, Path]:
    """Every service shipped in the kernel tree."""
    return {p.stem: p for p in sorted((ROOT / "plugins" / "services").glob("service_*.py"))}


def test_every_kernel_service_is_either_sandboxed_or_a_cited_exception():
    """No third category. A service either crosses the boundary or appears on
    the list with a reason."""
    unexplained = []
    for stem, path in _kernel_services().items():
        source = path.read_text(encoding="utf-8")
        on_contract = 'contract = "effects"' in source
        excepted = stem in TRUSTED_EXCEPTION
        if not on_contract and not excepted:
            unexplained.append(stem)

    assert not unexplained, (
        "These services neither use the effects contract nor appear in "
        "TRUSTED_EXCEPTION:\n  " + "\n  ".join(unexplained)
        + "\nEither convert them, or add them here citing one of: "
        + "; ".join(f"{n} = {d}" for n, d in CAPABILITIES.items())
    )


def test_the_exception_list_has_not_grown():
    """The count itself is the metric. If this fails because the list genuinely
    had to grow, update the number *and* say why in PRIMITIVES.md — the point is
    that it cannot happen without someone noticing."""
    assert len(TRUSTED_EXCEPTION) == 3, (
        f"the always-trusted exception now has {len(TRUSTED_EXCEPTION)} entries; "
        "growth here is the metric that the boundary is eroding"
    )


@pytest.mark.parametrize("stem,citation", sorted(TRUSTED_EXCEPTION.items()))
def test_each_exception_cites_a_capability(stem, citation):
    """A citation must name at least one of the five, so "it's special" is never
    a sufficient reason."""
    assert any(str(n) in citation for n in CAPABILITIES), \
        f"{stem} cites no capability: {citation!r}"


@pytest.mark.parametrize("stem", sorted(TRUSTED_EXCEPTION))
def test_listed_exceptions_still_exist(stem):
    """A stale entry is as bad as a missing one — it hides that the exception
    could have been retired."""
    assert stem in _kernel_services(), \
        f"{stem} is listed as a trusted exception but no longer exists"


def test_the_document_and_the_test_agree():
    """PRIMITIVES.md is the human-readable half of this test; they must not
    drift apart."""
    doc = (ROOT / "effects" / "PRIMITIVES.md").read_text(encoding="utf-8")
    assert "What requires the always-trusted exception" in doc
    for stem in TRUSTED_EXCEPTION:
        # service_parser is documented under the registry it owns.
        needle = "parser_registry" if stem == "service_parser" else stem
        assert needle in doc, f"{stem} is not documented in PRIMITIVES.md"


def test_the_compactor_proves_a_service_can_cross():
    """The list is only credible if something comparable *did* cross: compaction
    is a real kernel service doing real model work, on the contract."""
    source = (ROOT / "plugins" / "services" / "service_compactor.py").read_text(encoding="utf-8")

    assert 'contract = "effects"' in source
    assert '"complete"' in source
    assert "service_compactor" not in TRUSTED_EXCEPTION


# ── the entry points exist on the real classes ───────────────────────────
#
# Every family's kernel entry point is called through duck typing (the registry
# calls tool.perform, the loop calls compactor.perform), and every test double
# defines its own. So a base class that silently lost its entry point would pass
# the entire suite while breaking in production -- which is exactly what
# happened once: BaseService.perform was appended below the class body, nested
# inside a module-level function, and live compaction broke with 700+ tests
# green. These check the real classes.

ENTRY_POINTS = {
    "plugins.BaseTool": ("BaseTool", ["perform"]),
    "plugins.BaseCommand": ("BaseCommand", ["perform", "form_steps"]),
    "plugins.BaseTask": ("BaseTask", ["perform", "perform_event"]),
    "plugins.BaseService": ("BaseService", ["perform"]),
    "plugins.BaseFrontend": ("BaseFrontend", ["_render"]),
}


@pytest.mark.parametrize("module,spec", sorted(ENTRY_POINTS.items()))
def test_each_family_exposes_its_kernel_entry_points(module, spec):
    """The kernel calls these by name; if one is missing the family is broken
    at runtime no matter how green the suite is."""
    import importlib

    class_name, methods = spec
    cls = getattr(importlib.import_module(module), class_name)

    missing = [m for m in methods if not callable(getattr(cls, m, None))]
    assert not missing, f"{class_name} is missing kernel entry point(s): {missing}"


@pytest.mark.parametrize("module,spec", sorted(ENTRY_POINTS.items()))
def test_each_family_carries_the_effects_contract(module, spec):
    """One contract per family, and the mixin is where it lives."""
    import importlib

    from plugins.EffectsContract import EffectsContract

    cls = getattr(importlib.import_module(module), spec[0])
    assert issubclass(cls, EffectsContract)
    assert cls.contract == "legacy", "families default to legacy; plugins opt in"


def test_the_real_compactor_can_be_called_through_its_entry_point():
    """An end-to-end check on the one converted kernel service, because the
    doubles cannot catch a missing method on the real class."""
    from types import SimpleNamespace

    from plugins.services.service_compactor import CompactorService

    class _LLM:
        def invoke(self, messages):
            return SimpleNamespace(content="a summary", is_error=False)

    service = CompactorService()
    service._source_path = "plugins/services/service_compactor.py"
    context = SimpleNamespace(
        db=None, services={"llm": _LLM()}, runtime=None, session_key="s1", user_id=1,
        root_dir=".", approve_command=None, approval_denial_reason="",
        request_user_input=None, config={"sandbox_trust_all": True})

    assert service.perform("compact", {"transcript": "USER: hi"}, context) == "a summary"

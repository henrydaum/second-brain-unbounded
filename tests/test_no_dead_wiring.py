"""Every mechanism the kernel has must have someone feeding it.

This test exists because the same bug shipped four times in one migration:

- ``ServiceTicker`` was written and tested, and ``bootstrap`` never started it.
- ``ReloadPlugin`` had a vocabulary entry, a docstring and a test, and no context
  ever set ``EffectContext.reload_plugin``.
- ``effective_tier`` promised to derive a reload's danger from the target's
  declarations and only ever handled ``CallTool``.
- ``EffectContext.call_chain`` was ``()`` on every context in the system, so the
  recursion guard that reads it could never fire.

Every one of those passed a green suite, because unit tests construct an
``EffectContext`` by hand and fill in the field they are testing. The thing that
was missing was never the mechanism — it was the *production wiring*, and no
test that builds its own context can see that.

So this checks the join: for each field, is there real code outside ``tests/``
that sets it? It is a coarse check and it cannot prove the wiring is *correct*.
It can prove the wiring *exists*, which is the failure that keeps happening.
"""

from __future__ import annotations

import ast
from dataclasses import fields
from pathlib import Path

import pytest

from effects.interpreter import EffectContext

ROOT = Path(__file__).resolve().parents[1]

# Fields whose default is the whole intent — nothing needs to set them, and a
# producer would be the surprise. Each entry says why, so "add it to the
# exemptions" is never a silent way to make this test pass.
SELF_EXPLANATORY = {
    # Populated by the interpreter itself as a run proceeds, not by a builder.
    "taint": "the interpreter appends to it during a run",
    # Deliberately defaulted; production overrides only where policy differs.
    "denied_sql_identifiers": "defaults to the production denylist",
    "egress_gate": "defaults to the conservative gate; builders replace it after construction",
}


def _iter_source_files():
    """Every kernel .py file outside tests and the sandbox child trees."""
    skip = {"tests", ".venv", ".pytest_tmp", "store", "__pycache__"}
    for path in ROOT.rglob("*.py"):
        if any(part in skip for part in path.parts):
            continue
        yield path


def _assigned_keywords() -> dict[str, set[str]]:
    """Map ``keyword name -> {files that pass it}`` across the kernel.

    Keyword arguments rather than attribute writes, because that is how every
    context in this codebase is built: ``EffectContext(db=..., paths=...)``.
    Attribute assignment (``ectx.egress_gate = ...``) is counted too, since the
    gate is deliberately attached after construction.
    """
    found: dict[str, set[str]] = {}
    for path in _iter_source_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        rel = str(path.relative_to(ROOT)).replace("\\", "/")
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg:
                        found.setdefault(kw.arg, set()).add(rel)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute):
                        found.setdefault(target.attr, set()).add(rel)
    return found


@pytest.mark.parametrize("field_name", sorted(f.name for f in fields(EffectContext)))
def test_every_effect_context_field_is_populated_by_production_code(field_name):
    """A field nothing ever sets is a mechanism nothing can trigger."""
    if field_name in SELF_EXPLANATORY:
        pytest.skip(f"{field_name}: {SELF_EXPLANATORY[field_name]}")

    producers = _assigned_keywords().get(field_name, set())
    assert producers, (
        f"Nothing outside tests/ ever sets EffectContext.{field_name!r}.\n"
        f"That means the mechanism reading it can never fire in production, no "
        f"matter how many unit tests construct a context by hand and fill it in.\n"
        f"Either wire it where contexts are built (plugins/EffectsContract.py, "
        f"runtime/context.py), or — if it is genuinely defaulted on purpose — add "
        f"it to SELF_EXPLANATORY with the reason."
    )


def test_the_ticker_is_started_somewhere():
    """``tick_interval_s`` means nothing unless something calls the clock."""
    starters = [p for p in _iter_source_files()
                if "ServiceTicker(" in p.read_text(encoding="utf-8")
                and p.name != "service_ticker.py"]
    assert starters, "nothing constructs a ServiceTicker; ticked services never tick"


def test_borrowed_tiers_cover_every_request_that_claims_one():
    """A request declaring ``borrows_tier`` must be handled in ``effective_tier``.

    ``ReloadPlugin``'s docstring promised a borrowed tier for months while
    ``effective_tier`` graded it at the class-level floor, so every hot-reload
    was a flat egress. The claim is a class attribute rather than prose because
    the first version of this test read the docstrings and flagged
    ``TaskControl`` — whose docstring explains at length that it does *not*
    borrow. Inferring intent from English fails in exactly the place you need it
    to be exact.
    """
    from effects.vocabulary import REQUEST_TYPES

    source = (ROOT / "effects" / "interpreter.py").read_text(encoding="utf-8")
    body = source.split("def effective_tier")[1].split("\n    def ")[0]

    claims = sorted(cls.__name__ for cls in REQUEST_TYPES.values() if cls.borrows_tier)
    assert claims, "nothing declares borrows_tier; the mechanism has no users"

    missing = [name for name in claims if name not in body]
    assert not missing, (
        f"These request types declare borrows_tier but effective_tier does not "
        f"handle them: {missing}. The declaration is then a promise the code "
        f"does not keep, and they grade at the class-level floor.")


def test_nothing_handled_in_effective_tier_forgot_to_declare_it():
    """The other direction, so the two halves cannot drift apart quietly."""
    from effects.vocabulary import REQUEST_TYPES

    source = (ROOT / "effects" / "interpreter.py").read_text(encoding="utf-8")
    body = source.split("def effective_tier")[1].split("\n    def ")[0]

    undeclared = [cls.__name__ for cls in REQUEST_TYPES.values()
                  if not cls.borrows_tier and f"isinstance(request, {cls.__name__})" in body]
    assert not undeclared, (
        f"effective_tier special-cases {undeclared} but they do not declare "
        f"borrows_tier, so nothing else in the system knows their tier is a floor.")

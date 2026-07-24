"""sandbox_kit — pure helpers importable inside a sandboxed tool.

The art_kit analog for tools (see Second Brain Art), stripped to its honest
core: **pure computation only, no handles**. Every capability — files, db, the
network, the LLM — arrives at a tool as a *typed request it yields* to the
kernel interpreter, never as an object smuggled in here. So this module holds
nothing that touches the world: no I/O, no sockets, no db cursor, no clock it
didn't get as an argument. It is the shared arithmetic of tool-writing —
glob-to-regex, ranking, markdown formatting — factored out so the fiftieth tool
is ten lines instead of a hundred.

Why a plain importable module and not an injected namespace (art_kit's shape):
art_kit was injected only because it captured per-run canvas state (the
palette). Tools capture no such state, so a normal ``import sandbox_kit`` under
the child's import gate is simpler and needs no wiring. ``"sandbox_kit"`` is on
the allowlist in ``sandbox/validate.py``.

Conventions (kept from art_kit): deterministic given the inputs, docstrings
written for the LLM author (name the gotcha), lenient coercion inside, hard
errors only for genuinely unrecoverable shapes, ``_private`` internals. Add a
helper here the moment a *second* tool needs it — never a capability, and never
speculatively.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

# ── glob / paths ─────────────────────────────────────────────────────────
# Filesystem tools receive a flat listing from a ``ListDir`` request and do the
# matching themselves (matching is an algorithm, not a resource). These are the
# shared pieces of that work.


def compile_glob(pattern: str) -> "re.Pattern[str]":
    """Translate a glob into a compiled regex over '/'-separated relative paths.

    ``*`` and ``?`` never cross a separator; a ``**`` segment matches any number
    of directories. So ``*.py`` matches top-level files only, ``**/*.py`` any
    depth, ``src/**/*.ts`` a subtree. Case-insensitive. Match the result against
    the forward-slash relative paths a ``ListDir`` returns.
    """
    segments = [s for s in pattern.replace("\\", "/").split("/") if s]
    parts = []
    for seg in segments:
        if seg == "**":
            parts.append("(?:[^/]+/)*")
            continue
        piece = ""
        for ch in seg:
            if ch == "*":
                piece += "[^/]*"
            elif ch == "?":
                piece += "[^/]"
            else:
                piece += re.escape(ch)
        parts.append(piece + "/")
    body = "".join(parts)
    if body.endswith("/"):
        body = body[:-1]
    return re.compile("^" + body + "$", re.IGNORECASE)


def newest_first(entries: Iterable[dict], key: str = "mtime") -> list[dict]:
    """Return ``entries`` sorted newest-first by their ``key`` field (default
    ``mtime``). Entries missing the field sort oldest. Stable."""
    return sorted(entries, key=lambda e: e.get(key, 0) or 0, reverse=True)


def join_root(root: str, rel: str) -> str:
    """Join a ``ListDir`` root and a relative entry path with a forward slash —
    the shape tools echo back to the model and feed to ``ReadFiles``."""
    return root.replace("\\", "/").rstrip("/") + "/" + rel.replace("\\", "/").lstrip("/")


# ── validate ─────────────────────────────────────────────────────────────


def clamp(value: Any, lo: int, hi: int, default: int | None = None) -> int:
    """Coerce *value* to int and clamp to ``[lo, hi]``. A missing/garbage value
    falls back to ``default`` (or ``lo``). The workhorse for ``limit``-style
    params: ``clamp(params.get("limit"), 1, 500, 100)``."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = default if default is not None else lo
    return max(lo, min(hi, n))


# ── format ───────────────────────────────────────────────────────────────
# Tool output is markdown on the wire (CLAUDE.md). More builders (md_table,
# detail_card, quote_block — ports of plugins/frontends/helpers/formatters.py,
# unreachable in-sandbox) land here as tools that need them are ported.


def bullet_list(items: Iterable[Any]) -> str:
    """Render *items* as a ``- ``-prefixed markdown list, one per line."""
    return "\n".join("- " + str(i) for i in items)

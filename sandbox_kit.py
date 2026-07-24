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

import array
import re
from typing import Any, Iterable, Sequence

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


# ── lines / text ─────────────────────────────────────────────────────────


def truncate_chars(text: str, cap: int) -> tuple[str, bool]:
    """Clip *text* to ``cap`` characters on a newline boundary. Returns
    ``(text, truncated)``.

    Backs off to the last newline before ``cap`` so a line is never cut
    mid-way; with no newline in range it hard-cuts at ``cap``. The caller
    decides how to word the "truncated" note, so this composes with per-tool
    paging hints. ``cap <= 0`` or short text returns the text unchanged."""
    if cap <= 0 or len(text) <= cap:
        return text, False
    nl = text.rfind("\n", 0, cap)
    return (text[:nl] if nl != -1 else text[:cap]), True


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


# ── search / retrieval ─────────────────────────────────────────────────────
# Retrieval tools yield QueryDb / Embed and do the ranking here. Since a
# sandboxed tool can't import a sibling helper, this is where lexical, semantic,
# and hybrid share their arithmetic — the tools stay thin request-yielding shells.


def fts_query(text: str) -> str:
    """Prepare free text for an FTS5 ``MATCH``.

    If the text already uses FTS5 operators (quotes, ``AND``/``OR``/``NOT``,
    ``*``) it is passed through unchanged. Otherwise it is reduced to lowercased
    ``\\w+`` tokens joined by spaces (FTS5 implicitly ANDs them) — which also
    strips punctuation that would otherwise be a syntax error. Returns ``""`` if
    no searchable token survives. This is the sanitizer that makes it safe to
    inline the query into SQL text (``QueryDb`` binds no params)."""
    if any(op in text for op in ('"', " AND ", " OR ", " NOT ", "*")):
        return text.strip()
    tokens = re.findall(r"\w+", text.lower())
    return " ".join(tokens)


def sql_str(value: str) -> str:
    """Single-quote and escape a string literal for inlining into SQL, since
    ``QueryDb`` takes no bound parameters. ``o'brien`` → ``'o''brien'``."""
    return "'" + str(value).replace("'", "''") + "'"


def decode_f32(blob: bytes) -> list[float]:
    """Decode a float32 embedding blob (as written by numpy ``tobytes``) into a
    plain list of floats — the stdlib stand-in for ``np.frombuffer(dtype=f32)``
    so semantic search needs no numpy inside the sandbox. Native byte order."""
    return list(array.array("f", blob)) if blob else []


def cosine_top_k(query_vec: Sequence[float], rows: Iterable[tuple], k: int) -> list[tuple]:
    """Rank ``(payload, vec)`` rows against ``query_vec`` and return the top ``k``
    as ``(payload, score)``, best first.

    Score is the dot product — embeddings are stored L2-normalized, so dot ==
    cosine. Rows whose vector length doesn't match ``query_vec`` (stale
    embeddings from a different model) are skipped. Pure; no numpy."""
    dim = len(query_vec)
    scored = []
    for payload, vec in rows:
        if len(vec) != dim:
            continue
        scored.append((payload, sum(a * b for a, b in zip(query_vec, vec))))
    scored.sort(key=lambda pair: pair[1], reverse=True)
    return scored[: max(0, k)]


def search_summary(query: str, results: Sequence[dict], limit: int = 5) -> str:
    """Standard LLM-facing summary for a list of search-result dicts (each with
    ``path``, ``score``, and optional ``content``). Shows up to ``limit`` lines
    with a 120-char snippet, then a ``[+N more]`` tail. Shared by every search
    tool so their output reads identically."""
    if not results:
        return f'No results found for "{query}".'
    lines = [f'Found {len(results)} result(s) for "{query}":']
    for r in results[:limit]:
        snippet = (r.get("content") or "").replace("\n", " ")[:120]
        lines.append(f'- {r["path"]} (score {float(r.get("score", 0)):.2f}): "{snippet}..."')
    if len(results) > limit:
        lines.append(f"[+{len(results) - limit} more]")
    return "\n".join(lines)


# ── format ───────────────────────────────────────────────────────────────
# Tool output is markdown on the wire (CLAUDE.md). These mirror
# plugins/frontends/helpers/formatters.py (unreachable in-sandbox) so tool
# output renders identically to command output on every frontend.


def bullet_list(items: Iterable[Any]) -> str:
    """Render *items* as a ``- ``-prefixed markdown list, one per line."""
    return "\n".join("- " + str(i) for i in items)


def md_table(headers: list, rows: list) -> str:
    """Build a GitHub-style markdown table from headers and row tuples.

    Newlines in cells become spaces and ``|`` is escaped, so a cell can never
    break the table. Start it in its own block (blank line before) or GFM
    parsers fold it into the preceding paragraph."""
    def cell(value) -> str:
        return str("" if value is None else value).replace("\n", " ").replace("|", "\\|")
    lines = ["| " + " | ".join(cell(h) for h in headers) + " |",
             "|" + "|".join(" --- " for _ in headers) + "|"]
    lines += ["| " + " | ".join(cell(v) for v in row) + " |" for row in rows]
    return "\n".join(lines)

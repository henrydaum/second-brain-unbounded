"""search_tools — the agent's discovery half of the two-tool interface.

The agent no longer carries a catalog of tool schemas. It carries exactly two
tools: ``search_tools`` (this one) and ``execute_tool``. Every other capability
is found by describing what you want; this tool ranks the registered catalog by
a lexical BM25 score over each tool's one-line description and returns the best
matches. The agent then hands a chosen name to ``execute_tool``.

Per-tool context cost is therefore one catalog line at search time, not a full
schema on every turn — so the catalog can grow to hundreds or thousands of tools
without inflating the agent's context.

BM25 is deliberately dependency-free (stdlib tokenizer): good enough at current
catalog sizes, and an embedding upgrade can slot in behind the same tool later.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from plugins.BaseTool import BaseTool, ToolResult

# Tools that make up the two-tool interface itself — never search results.
_KERNEL_TOOLS = {"search_tools", "execute_tool", "abort_fill"}
_TOKEN = re.compile(r"[a-z0-9]+")
# BM25 free parameters (Robertson/Sparck-Jones defaults).
_K1 = 1.5
_B = 0.75


def _tokens(text: str) -> list[str]:
    """Lowercase alphanumeric tokens, split on camelCase and underscores."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text or "")
    return _TOKEN.findall(spaced.lower())


def _bm25_rank(query: str, docs: list[tuple[str, str]], limit: int) -> list[tuple[str, float]]:
    """Rank ``docs`` (``(name, text)``) against ``query`` by BM25.

    Returns ``[(name, score), ...]`` for the top ``limit`` positive-scoring
    docs, most relevant first.
    """
    q_terms = _tokens(query)
    if not q_terms or not docs:
        return []
    tokenized = [(name, _tokens(text)) for name, text in docs]
    n = len(tokenized)
    avgdl = sum(len(toks) for _, toks in tokenized) / n if n else 0.0
    # Document frequency per query term.
    df: Counter[str] = Counter()
    for _, toks in tokenized:
        seen = set(toks)
        for t in set(q_terms):
            if t in seen:
                df[t] += 1
    scored: list[tuple[str, float]] = []
    for name, toks in tokenized:
        if not toks:
            continue
        tf = Counter(toks)
        dl = len(toks)
        score = 0.0
        for t in q_terms:
            if t not in tf:
                continue
            idf = math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5))
            freq = tf[t]
            denom = freq + _K1 * (1 - _B + _B * dl / avgdl) if avgdl else freq + _K1
            score += idf * (freq * (_K1 + 1)) / denom
        if score > 0:
            scored.append((name, score))
    scored.sort(key=lambda pair: pair[1], reverse=True)
    return scored[:limit]


class SearchTools(BaseTool):
    """Find capabilities by description; the agent's tool-discovery tool."""

    name = "search_tools"
    description = (
        "Search the tool catalog for a capability. Describe what you want to do "
        "in a few words; returns the best-matching tool names with one-line "
        "descriptions. Then call execute_tool with the name you want. This is "
        "how you access every capability beyond search_tools/execute_tool."
    )
    parameters = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "What you want to do, in a few words (e.g. 'read a file', 'search the web').",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of tools to return (default 10).",
                "default": 10,
            },
        },
        "required": ["query"],
    }
    max_calls = 15
    background_safe = True

    agent_prompt = (
        "You have exactly two tools: `search_tools` and `execute_tool`. To do "
        "anything beyond plain conversation, first `search_tools` with a short "
        "description of what you need, then `execute_tool(name, intent)` with a "
        "chosen tool name and a one-sentence statement of why you're using it. "
        "You will then be asked to fill in that tool's parameters (or abort if "
        "it was the wrong choice). Never guess a tool name — search for it."
    )

    def _catalog(self, context) -> list[tuple[str, str]]:
        """All searchable tools as ``(name, name + description)`` documents."""
        registry = context.tool_registry
        tools = (getattr(registry, "tools", {}) or {}) if registry else {}
        docs = []
        for tool_name, tool in tools.items():
            if tool_name in _KERNEL_TOOLS:
                continue
            desc = (getattr(tool, "description", "") or "").strip()
            docs.append((tool_name, f"{tool_name} {desc}"))
        return docs

    def run(self, context, **kwargs) -> ToolResult:
        """Rank the catalog against the query and return the top matches."""
        query = (kwargs.get("query") or "").strip()
        if not query:
            return ToolResult.failed("search_tools needs a non-empty query.")
        try:
            limit = max(1, min(25, int(kwargs.get("limit", 10))))
        except (TypeError, ValueError):
            limit = 10

        docs = self._catalog(context)
        if not docs:
            return ToolResult(
                success=True,
                llm_summary="No tools are installed. Answer the user directly.",
                data={"results": []},
            )
        ranked = _bm25_rank(query, docs, limit)
        registry = context.tool_registry
        tools = getattr(registry, "tools", {}) or {}
        if not ranked:
            return ToolResult(
                success=True,
                llm_summary=(
                    f"No tool matched '{query}'. Try different words, or answer "
                    "the user directly if no tool fits."
                ),
                data={"results": []},
            )
        lines = []
        results = []
        for tool_name, score in ranked:
            desc = (getattr(tools.get(tool_name), "description", "") or "").strip()
            one_line = desc.splitlines()[0] if desc else "(no description)"
            lines.append(f"- `{tool_name}` — {one_line}")
            results.append({"name": tool_name, "description": one_line, "score": round(score, 3)})
        summary = (
            f"Top {len(results)} tool(s) for '{query}':\n" + "\n".join(lines)
            + "\n\nCall execute_tool with the name you want."
        )
        return ToolResult(success=True, llm_summary=summary, data={"results": results})

"""lexical_search — BM25 keyword search over the FTS5 lexical index.

Yields QueryDb (read-tier) over ``lexical_index``/``lexical_content`` and a
second QueryDb for per-path modality. All ranking/formatting is pure kit work;
the tool is a thin request shell. Inert until the indexing-pipeline package has
populated the FTS5 tables. Since QueryDb binds no params, free text is passed
through ``kit.fts_query`` (sanitizes to safe tokens) and every value is inlined
with ``kit.sql_str``.
"""

import sandbox_kit as kit
from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import QueryDb, Respond


class LexicalSearchTool(BaseSandboxTool):
    name = "lexical_search"
    description = (
        "Search indexed files by keyword using BM25-ranked full-text search over "
        "all indexed text (chunks, OCR, tabular). Supports FTS5 syntax: \"exact "
        "phrase\", term1 AND term2, term1 OR term2, NOT term, prefix*. Plain "
        "keywords are ANDed. Use for error strings, identifiers, and rare terms."
    )
    parameters = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query. FTS5 syntax supported (phrases, AND/OR/NOT, prefix*)."},
            "top_k": {"type": "integer", "description": "Max results. Default 5.", "default": 5},
            "sources": {"type": "array", "items": {"type": "string"}, "description": "Filter by content source, e.g. [\"extracted\", \"ocr\", \"tabular\"]. Omit for all."},
            "folder": {"type": "string", "description": "Restrict to files under this folder path."},
        },
        "required": ["query"],
    }
    fill_prompt = "Give the `query`. Use FTS5 syntax for phrases/booleans; set `top_k`, `sources`, or `folder` to narrow."
    declared_requests = ["query_db"]
    view = "params_only"
    max_calls = 10
    background_safe = True

    def run(self, params):
        query = (params.get("query") or "").strip()
        if not query:
            return Respond(summary="lexical_search failed: no query provided.", success=False, error="no query")
        match = kit.fts_query(query)
        if not match:
            return Respond(summary="lexical_search failed: the query produced no searchable terms.",
                           success=False, error="empty query")
        top_k = kit.clamp(params.get("top_k"), 1, 500, 5)

        res = yield QueryDb(sql=_search_sql(match, params.get("sources"), params.get("folder"), top_k),
                            max_rows=top_k)
        if not res.ok:
            return Respond(summary="lexical_search failed: " + res.error, success=False, error=res.error)
        rows = (res.value or {}).get("rows", [])
        if not rows:
            return Respond(summary=f'No results found for "{query}".', data=[])

        modality = yield from _modality_map(sorted({r[0] for r in rows}))
        results = [_result(path, chunk_index, content, source, rank, modality)
                   for path, chunk_index, content, source, rank in rows]
        return Respond(summary=kit.search_summary(query, results), data=results,
                       attachment_paths=sorted({r["path"] for r in results}))


# ── retrieval pieces ─────────────────────────────────────────────────────────
# Schema-specific SQL for the FTS5 index. The *general* arithmetic (fts_query,
# search_summary, sql_str) lives in sandbox_kit; this index schema is a store
# package's, so it stays here. hybrid_search duplicates this small glue rather
# than importing it — sandboxed tools can't import a sibling file.

def _search_sql(match, sources, folder, top_k) -> str:
    """Build the FTS5 SELECT with optional source/folder filters, values inlined."""
    sql = [
        "SELECT sc.path, sc.chunk_index, sc.content, sc.source, si.rank",
        "FROM lexical_index si",
        "JOIN lexical_content sc ON si.rowid = sc.rowid",
        f"WHERE lexical_index MATCH {kit.sql_str(match)}",
    ]
    if sources:
        joined = ", ".join(kit.sql_str(s) for s in sources)
        sql.append(f"AND sc.source IN ({joined})")
    if folder:
        norm = folder.replace("\\", "/").rstrip("/")
        sql.append("AND (replace(sc.path, char(92), '/') = " + kit.sql_str(norm)
                   + " OR replace(sc.path, char(92), '/') LIKE " + kit.sql_str(norm + "/%") + ")")
    sql.append("ORDER BY si.rank")
    sql.append(f"LIMIT {int(top_k)}")
    return "\n".join(sql)


def _modality_map(paths):
    """Yield a QueryDb over the files table → {path: modality}. A generator so
    callers delegate with ``yield from``."""
    if not paths:
        return {}
    joined = ", ".join(kit.sql_str(p) for p in paths)
    res = yield QueryDb(sql=f"SELECT path, modality FROM files WHERE path IN ({joined})",
                        max_rows=len(paths))
    return {row[0]: row[1] for row in (res.value or {}).get("rows", [])} if res.ok else {}


def _result(path, chunk_index, content, source, rank, modality) -> dict:
    """One lexical SearchResult dict (FTS5 rank is negative; invert so higher=better)."""
    return {
        "path": path,
        "score": -1.0 * float(rank),
        "source": source,
        "stream": "lexical",
        "modality": modality.get(path, "unknown"),
        "content": content,
        "chunk_index": int(chunk_index) if chunk_index is not None else None,
    }

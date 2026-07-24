"""hybrid_search — fuse lexical + semantic retrieval with Reciprocal Rank Fusion.

The original called the lexical/semantic tools via ``context.call_tool``. A
sandboxed tool cannot call another tool, so this inlines both retrievals (the
same QueryDb / Embed requests the sibling tools yield) and fuses them. The RRF
math is pure and lives here; the general arithmetic (fts_query, cosine_top_k,
decode_f32, search_summary) is shared through ``sandbox_kit``. Inert until the
indexing-pipeline package has populated the index tables.
"""

import sandbox_kit as kit
from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import Embed, QueryDb, Respond

RRF_K = 60  # standard constant from the RRF paper; higher = flatter rank weighting
_CONTENT_FIELDS = ("content", "score", "chunk_index")


class HybridSearchTool(BaseSandboxTool):
    name = "hybrid_search"
    description = (
        "Search indexed files using both keyword and semantic retrieval, then fuse "
        "the results (Reciprocal Rank Fusion) for better ranking. Prefer this over "
        "lexical_search or semantic_search alone when finding local files or excerpts. "
        "Optional folder/modality filters narrow the search."
    )
    parameters = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "What to search for in the indexed local files."},
            "max_results": {"type": "integer", "description": "Max total results. Default 5.", "default": 5},
            "folder": {"type": "string", "description": "Restrict to files under this folder path."},
            "modality": {"type": "string", "description": "Restrict to a file modality, e.g. \"text\". Omit for all."},
        },
        "required": ["query"],
    }
    fill_prompt = "Give the `query`; set `max_results`, `folder`, or `modality` to narrow. This fuses keyword + semantic ranking."
    agent_prompt = (
        "## Searching indexed files\n"
        "Three retrieval tools search the indexed corpus (your sync directories plus "
        "dropped-in attachments); files outside the index are not searchable — use "
        "read_file for a path you already know.\n"
        "- hybrid_search: fuses keyword + semantic ranking. Default for finding local files/excerpts.\n"
        "- lexical_search: exact keyword/identifier/code matching (error strings, function names).\n"
        "- semantic_search: meaning-based retrieval for paraphrased or conceptual questions.\n"
        "Results are excerpts grouped by document; follow up with read_file for full context."
    )
    declared_requests = ["query_db", "embed"]
    view = "params_only"
    max_calls = 10
    background_safe = True

    def run(self, params):
        query = (params.get("query") or "").strip()
        if not query:
            return Respond(summary="hybrid_search failed: no query provided.", success=False, error="no query")
        max_results = kit.clamp(params.get("max_results"), 1, 100, 5)
        folder = params.get("folder")
        modality = params.get("modality")
        fetch = max(200, max_results * 10)

        lex = yield from _lexical_hits(query, folder, fetch)
        sem = yield from _semantic_hits(query, folder, fetch)
        raw = lex + sem
        if modality:
            raw = [r for r in raw if r.get("modality") == modality]
        if not raw:
            return Respond(summary=f'No results found for "{query}".', data=[])

        docs = _fuse(raw)[:max_results]
        return Respond(summary=kit.search_summary(query, docs), data=docs,
                       attachment_paths=[d["path"] for d in docs])


# ── inlined retrieval (schema glue mirrors the sibling tools) ────────────────

def _lexical_hits(query, folder, top_k):
    match = kit.fts_query(query)
    if not match:
        return []
    sql = ["SELECT sc.path, sc.chunk_index, sc.content, sc.source, si.rank",
           "FROM lexical_index si JOIN lexical_content sc ON si.rowid = sc.rowid",
           f"WHERE lexical_index MATCH {kit.sql_str(match)}"]
    if folder:
        norm = folder.replace("\\", "/").rstrip("/")
        sql.append("AND (replace(sc.path, char(92), '/') = " + kit.sql_str(norm)
                   + " OR replace(sc.path, char(92), '/') LIKE " + kit.sql_str(norm + "/%") + ")")
    sql.append(f"ORDER BY si.rank LIMIT {int(top_k)}")
    res = yield QueryDb(sql="\n".join(sql), max_rows=top_k)
    if not res.ok:
        return []
    rows = (res.value or {}).get("rows", [])
    modality = yield from _modality_map(sorted({r[0] for r in rows}))
    return [{"path": p, "score": -1.0 * float(rank), "source": src, "stream": "lexical",
             "modality": modality.get(p, "unknown"), "content": content,
             "chunk_index": int(ci) if ci is not None else None}
            for p, ci, content, src, rank in rows]


def _semantic_hits(query, folder, top_k):
    emb = yield Embed(inputs=[query])
    if not emb.ok:
        return []  # no embedder installed — hybrid degrades to lexical-only
    vectors = (emb.value or {}).get("vectors") or []
    if not vectors:
        return []
    query_vec, model = vectors[0], (emb.value or {}).get("model") or ""
    sql = f"SELECT path, chunk_index, embedding FROM text_embeddings WHERE model_name = {kit.sql_str(model)}"
    if folder:
        sql += " AND path LIKE " + kit.sql_str(folder.replace("\\", "/").rstrip("/") + "%")
    res = yield QueryDb(sql=sql, max_rows=100000)
    if not res.ok:
        return []
    rows = [((r[0], r[1]), kit.decode_f32(r[2])) for r in (res.value or {}).get("rows", []) if r[2]]
    ranked = kit.cosine_top_k(query_vec, rows, top_k)
    if not ranked:
        return []
    keys = [key for key, _ in ranked]
    content = yield from _content_map(keys)
    modality = yield from _modality_map(sorted({p for p, _ in keys}))
    return [{"path": path, "score": float(score), "source": "text_embedding", "stream": "text_semantic",
             "modality": modality.get(path, "unknown"), "content": content.get((path, idx)),
             "chunk_index": int(idx) if idx is not None else None}
            for (path, idx), score in ranked]


def _content_map(keys):
    if not keys:
        return {}
    clauses = " OR ".join(f"(path = {kit.sql_str(p)} AND chunk_index = {int(i)})" for p, i in keys)
    res = yield QueryDb(sql=f"SELECT path, chunk_index, content FROM text_chunks WHERE {clauses}",
                        max_rows=len(keys))
    return {(row[0], row[1]): row[2] for row in (res.value or {}).get("rows", [])} if res.ok else {}


def _modality_map(paths):
    if not paths:
        return {}
    joined = ", ".join(kit.sql_str(p) for p in paths)
    res = yield QueryDb(sql=f"SELECT path, modality FROM files WHERE path IN ({joined})", max_rows=len(paths))
    return {row[0]: row[1] for row in (res.value or {}).get("rows", [])} if res.ok else {}


# ── fusion (pure) ────────────────────────────────────────────────────────────

def _fuse(raw):
    """Group by stream, collapse chunks into documents, RRF across streams, and
    return documents sorted by fused score (best first)."""
    by_stream = {}
    for r in raw:
        by_stream.setdefault(r["stream"], []).append(r)
    deduped = {name: _dedup_by_path(rows) for name, rows in by_stream.items()}

    scores, merged = {}, {}
    for name, docs in deduped.items():
        docs.sort(key=lambda d: d["score"], reverse=True)
        kind = "Lexical" if name == "lexical" else "Semantic"
        for rank, doc in enumerate(docs):
            path = doc["path"]
            scores[path] = scores.get(path, 0.0) + 1.0 / (RRF_K + rank + 1)
            if path not in merged:
                merged[path] = dict(doc)
                merged[path]["result_type"] = kind
            else:
                stored = merged[path]
                if stored["result_type"] != kind:
                    stored["result_type"] = "Hybrid"
                stored["num_hits"] += doc["num_hits"]
                if doc["score"] > stored["score"]:
                    _update_content(stored, doc)
                stored["source"] = ", ".join(sorted(set(stored["source"].split(", ")) | set(doc["source"].split(", "))))
    for path, doc in merged.items():
        doc["score"] = scores[path]
    return sorted(merged.values(), key=lambda d: d["score"], reverse=True)


def _dedup_by_path(results):
    """Collapse a stream's chunks of one file into a single document, keeping the
    best-scoring chunk's content and counting hits."""
    by_path = {}
    for res in results:
        path = res["path"]
        if path not in by_path:
            by_path[path] = dict(res)
            by_path[path]["num_hits"] = 1
        else:
            stored = by_path[path]
            stored["num_hits"] += 1
            if res["score"] > stored["score"]:
                _update_content(stored, res)
    return list(by_path.values())


def _update_content(target, source):
    for field in _CONTENT_FIELDS:
        if field in source:
            target[field] = source[field]

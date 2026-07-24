"""semantic_search — vector-similarity search over the text embedding stream.

Yields Embed (egress; the kernel holds the embedder, keys never enter the
sandbox) to encode the query, then QueryDb to load stored embeddings, decodes
the float32 blobs with ``kit.decode_f32`` and ranks with ``kit.cosine_top_k``
(pure stdlib — no numpy in the sandbox). Inert until the indexing-pipeline
package has populated ``text_embeddings``/``text_chunks``.

The original searched multiple embedder streams (text, image) via per-stream
services. The sandbox exposes exactly one embedder through the ``Embed``
request, so this port serves the text stream; multi-embedder routing waits on
the embedder being selectable per request.
"""

import sandbox_kit as kit
from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import Embed, QueryDb, Respond

SOURCE = "text_embedding"
STREAM = "text_semantic"


class SemanticSearchTool(BaseSandboxTool):
    name = "semantic_search"
    description = (
        "Search indexed files by meaning using vector similarity. Embeds your "
        "query and compares it against stored text embeddings, returning the most "
        "semantically similar chunks. Use for paraphrased or conceptual questions "
        "where exact wording won't match."
    )
    parameters = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Natural-language query to search for."},
            "top_k": {"type": "integer", "description": "Max results. Default 5.", "default": 5},
            "folder": {"type": "string", "description": "Restrict to files under this folder path."},
        },
        "required": ["query"],
    }
    fill_prompt = "Give a natural-language `query`; set `top_k` or `folder` to narrow."
    declared_requests = ["embed", "query_db"]
    view = "params_only"
    max_calls = 10
    background_safe = True

    def run(self, params):
        query = (params.get("query") or "").strip()
        if not query:
            return Respond(summary="semantic_search failed: no query provided.", success=False, error="no query")
        top_k = kit.clamp(params.get("top_k"), 1, 500, 5)

        emb = yield Embed(inputs=[query])
        if not emb.ok:
            return Respond(summary="semantic_search failed: " + (emb.error or "no embedder available."),
                           success=False, error=emb.error or "no embedder")
        vectors = (emb.value or {}).get("vectors") or []
        model = (emb.value or {}).get("model") or ""
        if not vectors:
            return Respond(summary="semantic_search failed: the embedder returned no vector.",
                           success=False, error="empty embedding")
        query_vec = vectors[0]

        results = yield from _semantic_hits(query_vec, model, params.get("folder"), top_k)
        if not results:
            return Respond(summary=f'No results found for "{query}".', data=[])
        return Respond(summary=kit.search_summary(query, results), data=results,
                       attachment_paths=sorted({r["path"] for r in results}))


# ── retrieval (hybrid_search duplicates this glue — no sibling imports) ───────

def _semantic_hits(query_vec, model, folder, top_k):
    """Generator: load embeddings, rank by cosine, hydrate content+modality.
    Returns a list of text_semantic SearchResult dicts."""
    sql = f"SELECT path, chunk_index, embedding FROM text_embeddings WHERE model_name = {kit.sql_str(model)}"
    if folder:
        sql += " AND path LIKE " + kit.sql_str(folder.replace("\\", "/").rstrip("/") + "%")
    res = yield QueryDb(sql=sql, max_rows=100000)
    if not res.ok:
        return []
    rows = [((row[0], row[1]), kit.decode_f32(row[2])) for row in (res.value or {}).get("rows", []) if row[2]]
    ranked = kit.cosine_top_k(query_vec, rows, top_k)  # [((path, idx), score)]
    if not ranked:
        return []

    keys = [key for key, _ in ranked]
    content = yield from _content_map(keys)
    modality = yield from _modality_map(sorted({p for p, _ in keys}))
    return [{
        "path": path,
        "score": float(score),
        "source": SOURCE,
        "stream": STREAM,
        "modality": modality.get(path, "unknown"),
        "content": content.get((path, idx)),
        "chunk_index": int(idx) if idx is not None else None,
    } for (path, idx), score in ranked]


def _content_map(keys):
    """Generator: QueryDb over text_chunks for (path, chunk_index) pairs →
    {(path, idx): content}."""
    if not keys:
        return {}
    clauses = " OR ".join(f"(path = {kit.sql_str(p)} AND chunk_index = {int(i)})" for p, i in keys)
    res = yield QueryDb(sql=f"SELECT path, chunk_index, content FROM text_chunks WHERE {clauses}",
                        max_rows=len(keys))
    return {(row[0], row[1]): row[2] for row in (res.value or {}).get("rows", [])} if res.ok else {}


def _modality_map(paths):
    """Generator: QueryDb over files → {path: modality}."""
    if not paths:
        return {}
    joined = ", ".join(kit.sql_str(p) for p in paths)
    res = yield QueryDb(sql=f"SELECT path, modality FROM files WHERE path IN ({joined})",
                        max_rows=len(paths))
    return {row[0]: row[1] for row in (res.value or {}).get("rows", [])} if res.ok else {}

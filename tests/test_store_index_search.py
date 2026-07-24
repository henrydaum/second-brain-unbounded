"""End-to-end characterization of the ported index-search tools.

lexical_search / semantic_search / hybrid_search loaded off the local store ref
and driven through the real subprocess runner + interpreter against a populated
index DB (FTS5 lexical tables + a text_embeddings/text_chunks corpus). These
tools are inert until the indexing-pipeline package builds those tables, so the
fixture stands in for that package.
"""

from __future__ import annotations

import array
import subprocess
from pathlib import Path

import pytest

import sandbox.runner as R
from effects import EffectContext
from pipeline.database import Database

_REPO = Path(__file__).resolve().parents[1]


def _store_source(rel: str) -> str | None:
    for ref in ("store", "origin/store"):
        proc = subprocess.run(
            ["git", "-C", str(_REPO), "show", f"{ref}:{rel}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", check=False)
        if proc.returncode == 0:
            return proc.stdout
    return None


@pytest.fixture(scope="module")
def sources():
    out = {name: _store_source(f"tools/tool_{name}.py")
           for name in ("lexical_search", "semantic_search", "hybrid_search")}
    if any(v is None for v in out.values()):
        pytest.skip("ported index-search tools not present on a local store ref")
    return out


class _FakeEmbedder:
    """Stand-in text embedder: deterministic unit vectors keyed to our corpus so
    cosine ranking is predictable. model_name matches the rows we seed."""
    model_name = "fake-embed-v1"
    loaded = True
    _VECS = {
        "cats and kittens": [1.0, 0.0, 0.0],
        "dogs and puppies": [0.0, 1.0, 0.0],
        "quarterly finance report": [0.0, 0.0, 1.0],
    }

    def encode(self, inputs):
        if isinstance(inputs, str):
            inputs = [inputs]
        return [self._VECS.get(t.strip().lower(), [0.0, 0.0, 0.0]) for t in inputs]


def _blob(vec):
    return array.array("f", vec).tobytes()


@pytest.fixture()
def db(tmp_path):
    d = Database(str(tmp_path / "index.db"))
    with d.lock:
        c = d.conn
        c.execute("CREATE VIRTUAL TABLE lexical_index USING fts5(content)")
        c.execute("CREATE TABLE lexical_content (rowid INTEGER PRIMARY KEY, path TEXT, chunk_index INTEGER, content TEXT, source TEXT)")
        # files already exists in the kernel schema — insert into it, don't recreate.
        c.execute("CREATE TABLE text_chunks (path TEXT, chunk_index INTEGER, content TEXT)")
        c.execute("CREATE TABLE text_embeddings (path TEXT, chunk_index INTEGER, embedding BLOB, model_name TEXT)")
        corpus = [
            (1, "notes/cats.md", 0, "cats and kittens", "extracted", "text", [1.0, 0.0, 0.0]),
            (2, "notes/dogs.md", 0, "dogs and puppies", "extracted", "text", [0.0, 1.0, 0.0]),
            (3, "reports/q1.md", 0, "quarterly finance report", "extracted", "text", [0.0, 0.0, 1.0]),
        ]
        for rowid, path, idx, content, source, modality, vec in corpus:
            c.execute("INSERT INTO lexical_index (rowid, content) VALUES (?, ?)", (rowid, content))
            c.execute("INSERT INTO lexical_content VALUES (?, ?, ?, ?, ?)", (rowid, path, idx, content, source))
            c.execute("INSERT INTO files (path, modality) VALUES (?, ?)", (path, modality))
            c.execute("INSERT INTO text_chunks VALUES (?, ?, ?)", (path, idx, content))
            c.execute("INSERT INTO text_embeddings VALUES (?, ?, ?, ?)", (path, idx, _blob(vec), _FakeEmbedder.model_name))
        c.commit()
    return d


def _run(source, name, declared, params, db, embedder=None):
    ctx = EffectContext(tool_name=name, read_roots=[Path(db.db_path).parent], db=db,
                        embedder=embedder, egress_gate=lambda r: (True, ""))
    return R.run_sandbox_tool(source=source, params=params, declared=declared,
                              effect_ctx=ctx, timeout=30)


# ── lexical_search ───────────────────────────────────────────────────────

def test_lexical_finds_by_keyword(sources, db):
    out = _run(sources["lexical_search"], "lexical_search", ["query_db"],
               {"query": "kittens"}, db)
    assert out.success and "notes/cats.md" in out.summary
    assert out.data[0]["path"] == "notes/cats.md" and out.data[0]["modality"] == "text"


def test_lexical_no_match(sources, db):
    out = _run(sources["lexical_search"], "lexical_search", ["query_db"],
               {"query": "elephants"}, db)
    assert out.success and "No results" in out.summary and out.data == []


def test_lexical_folder_filter(sources, db):
    out = _run(sources["lexical_search"], "lexical_search", ["query_db"],
               {"query": "report", "folder": "reports"}, db)
    assert out.success and all(r["path"].startswith("reports/") for r in out.data)


# ── semantic_search ──────────────────────────────────────────────────────

def test_semantic_ranks_by_similarity(sources, db):
    out = _run(sources["semantic_search"], "semantic_search", ["query_db", "embed"],
               {"query": "dogs and puppies"}, db, embedder=_FakeEmbedder())
    assert out.success and out.data[0]["path"] == "notes/dogs.md"
    assert out.data[0]["stream"] == "text_semantic"


def test_semantic_no_embedder(sources, db):
    out = _run(sources["semantic_search"], "semantic_search", ["query_db", "embed"],
               {"query": "anything"}, db, embedder=None)
    assert out.success is False


# ── hybrid_search ────────────────────────────────────────────────────────

def test_hybrid_fuses_streams(sources, db):
    out = _run(sources["hybrid_search"], "hybrid_search", ["query_db", "embed"],
               {"query": "cats and kittens"}, db, embedder=_FakeEmbedder())
    assert out.success and out.data[0]["path"] == "notes/cats.md"


def test_hybrid_dedups_to_documents(sources, db):
    out = _run(sources["hybrid_search"], "hybrid_search", ["query_db", "embed"],
               {"query": "quarterly finance report"}, db, embedder=_FakeEmbedder())
    assert out.success
    paths = [r["path"] for r in out.data]
    assert len(paths) == len(set(paths))  # one entry per document

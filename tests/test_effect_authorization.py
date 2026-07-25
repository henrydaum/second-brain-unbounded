"""Resolution-time authorization: the arguments decide, not the verb.

A request's *tier* is derived from its type, but whether a given call is
permitted is a property of what it names — the path it resolves to, the URL's
scheme, the tables the SQL touches. These tests pin that second check.

The path cases are characterization tests: ``_check_path`` already handles them
correctly (``Path.relative_to`` compares components, not string prefixes, and
``resolve()`` collapses symlinks before the comparison). They exist so a future
refactor toward string prefixing fails loudly.
"""

from __future__ import annotations

import pytest

from effects.interpreter import EffectContext, Interpreter
from effects.vocabulary import (
    ExecSql,
    HttpRequest,
    QueryDb,
    ReadFile,
    WriteDb,
)


def _interp(tmp_path, declared, **kw):
    """An interpreter confined to ``tmp_path/src`` for reads and writes."""
    root = tmp_path / "src"
    root.mkdir(exist_ok=True)
    ctx = EffectContext(read_roots=[root], write_roots=[root], **kw)
    return Interpreter(ctx, declared)


# ── filesystem confinement (characterization) ────────────────────────────

def test_sibling_root_with_shared_prefix_is_not_reachable(tmp_path):
    """``src2`` must not be reachable from a grant over ``src``."""
    sibling = tmp_path / "src2"
    sibling.mkdir()
    (sibling / "secret.txt").write_text("leak", encoding="utf-8")

    result = _interp(tmp_path, ["read_file"]).fulfill(
        ReadFile(path=str(sibling / "secret.txt")))

    assert not result.ok
    assert "outside the allowed read roots" in result.error


def test_parent_traversal_is_refused(tmp_path):
    """``../`` out of the root resolves before the check, so it is refused."""
    (tmp_path / "outside.txt").write_text("leak", encoding="utf-8")

    result = _interp(tmp_path, ["read_file"]).fulfill(
        ReadFile(path=str(tmp_path / "src" / ".." / "outside.txt")))

    assert not result.ok
    assert "outside the allowed read roots" in result.error


def test_symlink_out_of_the_root_is_refused(tmp_path):
    """A symlink inside the root pointing out resolves to its target first."""
    outside = tmp_path / "outside.txt"
    outside.write_text("leak", encoding="utf-8")
    root = tmp_path / "src"
    root.mkdir(exist_ok=True)
    try:
        (root / "escape").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks not permitted on this host")

    result = _interp(tmp_path, ["read_file"]).fulfill(
        ReadFile(path=str(root / "escape")))

    assert not result.ok
    assert "outside the allowed read roots" in result.error


# ── egress URLs ──────────────────────────────────────────────────────────

def _allow_all(_request):
    """An egress gate that approves everything (isolates the URL check)."""
    return True, ""


def test_file_url_cannot_launder_a_local_read_through_http(tmp_path):
    """``file://`` is a local read wearing an egress badge — it would bypass
    read_roots entirely, so the scheme allowlist must refuse it even when the
    egress gate approves."""
    outside = tmp_path / "outside.txt"
    outside.write_text("leak", encoding="utf-8")

    result = _interp(tmp_path, ["http_request"], egress_gate=_allow_all).fulfill(
        HttpRequest(method="GET", url=outside.as_uri()))

    assert not result.ok
    assert "leak" not in str(result.value)
    assert "scheme" in result.error


@pytest.mark.parametrize("url", [
    "ftp://example.com/x",
    "data:text/plain,hello",
    "gopher://example.com",
])
def test_non_http_schemes_are_refused(tmp_path, url):
    """Only http/https reach the network; everything else is refused."""
    result = _interp(tmp_path, ["http_request"], egress_gate=_allow_all).fulfill(
        HttpRequest(method="GET", url=url))

    assert not result.ok
    assert "scheme" in result.error


def test_credentials_in_a_url_are_refused(tmp_path):
    """``user:pass@host`` would leak a secret into ledger rows and the approval
    dialog, so the URL is refused before it is placed."""
    result = _interp(tmp_path, ["http_request"], egress_gate=_allow_all).fulfill(
        HttpRequest(method="GET", url="https://user:pw@example.com/x"))

    assert not result.ok
    assert "credentials" in result.error


def test_link_local_metadata_endpoint_is_refused(tmp_path):
    """169.254.169.254 is an unauthenticated cloud-credential source."""
    result = _interp(tmp_path, ["http_request"], egress_gate=_allow_all).fulfill(
        HttpRequest(method="GET", url="http://169.254.169.254/latest/meta-data/"))

    assert not result.ok
    assert "link-local" in result.error


# ── SQL table scoping ────────────────────────────────────────────────────

class _RecordingDb:
    """A db that records what SQL reached it, so a refusal is provably a
    refusal-before-execution rather than an empty result."""

    def __init__(self):
        self.seen: list[str] = []

    def query(self, sql, max_rows=100):
        self.seen.append(sql)
        return {"columns": ["password_hash"], "rows": [["hash"]], "truncated": False}

    def execute_write(self, sql):
        self.seen.append(sql)
        return 1

    def ensure_output_table(self, table, schema_sql):
        self.seen.append(schema_sql)

    def write_outputs(self, table, rows):
        self.seen.append(f"insert {table}")


@pytest.mark.parametrize("sql", [
    "SELECT password_hash FROM users",
    'SELECT * FROM "users"',
    "SELECT * FROM main.users",
    "SELECT * FROM users u WHERE u.id = 1",
    "WITH c AS (SELECT * FROM users) SELECT * FROM c",
])
def test_query_db_cannot_read_the_credential_table(tmp_path, sql):
    """read-tier does not mean every row is fair game: ``users`` holds
    password hashes and the per-user config blob, and read composes with the
    default-allowed ``Complete`` into exfiltration."""
    db = _RecordingDb()
    result = _interp(tmp_path, ["query_db"], db=db).fulfill(QueryDb(sql=sql))

    assert not result.ok
    assert "not readable" in result.error
    assert db.seen == []  # refused before it reached the database


def test_exec_sql_cannot_mutate_the_credential_table(tmp_path):
    """The same identifier gate applies to the mutation verb."""
    db = _RecordingDb()
    result = _interp(tmp_path, ["exec_sql"], db=db, egress_gate=_allow_all).fulfill(
        ExecSql(sql="UPDATE users SET password_hash = 'x'"))

    assert not result.ok
    assert db.seen == []


def test_write_db_cannot_target_the_credential_table(tmp_path):
    """A task-owned output table may not be named ``users``."""
    db = _RecordingDb()
    result = _interp(tmp_path, ["write_db"], db=db).fulfill(
        WriteDb(table="users", schema_sql="CREATE TABLE users (id INTEGER)", rows=[{"id": 1}]))

    assert not result.ok
    assert db.seen == []


def test_ordinary_tables_are_unaffected(tmp_path):
    """The gate is a targeted denial, not a general restriction — normal
    queries must still reach the database."""
    db = _RecordingDb()
    result = _interp(tmp_path, ["query_db"], db=db).fulfill(
        QueryDb(sql="SELECT * FROM conversation_messages LIMIT 5"))

    assert result.ok
    assert len(db.seen) == 1


# ── the deferred-execution rule ──────────────────────────────────────────

def test_plugin_tree_is_not_a_free_write_root():
    """Writing into a tree the kernel *interprets* is escalation, not a write.

    ``discover_tools`` instantiates every ``BaseTool`` subclass found under the
    sandbox plugin root and runs it in-process with the live context. If that
    tree were approval-free, a sandboxed tool could author a plain (non-sandboxed)
    plugin and be running with full authority on the next load — a complete
    escape. The tree stays inside ``write_roots`` so authoring still works; it
    just costs one approval. See the deferred-execution rule in PRIMITIVES.md.
    """
    from types import SimpleNamespace

    from paths import SANDBOX_PLUGINS
    from plugins.BaseTool import BaseTool

    class _Probe(BaseTool):
        name = "probe"
        description = "probe"
        contract = "effects"

    probe = _Probe()
    context = SimpleNamespace(config={}, user_id=1, root_dir=None)
    free = [str(p) for p in probe._free_write_roots(context)]

    assert str(SANDBOX_PLUGINS) not in free
    # …but it must remain writable-with-approval, or authoring breaks entirely.
    assert any(str(SANDBOX_PLUGINS).startswith(str(p)) for p in probe._write_roots(context))

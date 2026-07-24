"""The closed request vocabulary — the wire format of the whole system.

Every effect a tool can ask for is one of the frozen dataclasses below. Each
carries two class-level constants:

- ``type``: the wire tag (stable string; the JSON discriminator on the pipe and
  the ``name`` in the ledger).
- ``tier``: ``read`` | ``write`` | ``egress`` — the security grade. A tool's
  danger tier is the max tier across the request types it declares.

``to_wire()`` / ``from_wire()`` round-trip a request to tagged JSON. This is the
exact payload that crosses the subprocess pipe (``{"type": ..., <fields>}``) and
the exact shape stored in the ledger's ``args_json``. Keep the fields plain and
JSON-serializable — no nested dataclasses, no callables.

This module has **no dependencies** on the rest of the kernel on purpose: it is
imported by the sandbox child (which runs under ``python -I`` with a restricted
import gate), by the interpreter, by the ledger, and eventually by the
conversation-DAG layer. Adding a request type means adding a frozen dataclass
here and a handler in ``effects.interpreter``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Any, ClassVar

# ── tiers ────────────────────────────────────────────────────────────────
TIER_READ = "read"
TIER_WRITE = "write"
TIER_EGRESS = "egress"

# Ordering so ``max(tier, ...)`` is meaningful: a tool that both reads and
# egresses is an egress-tier tool.
TIER_ORDER: dict[str, int] = {TIER_READ: 0, TIER_WRITE: 1, TIER_EGRESS: 2}


class Request:
    """Base for every typed request. Subclasses are frozen dataclasses.

    Not a dataclass itself (it declares no fields) so subclasses control their
    own field order without base-field interference.
    """

    type: ClassVar[str] = ""
    tier: ClassVar[str] = TIER_READ

    def to_wire(self) -> dict[str, Any]:
        """Serialize to tagged JSON-ready dict: ``{"type": tag, <fields>}``."""
        return {"type": self.type, **asdict(self)}  # type: ignore[call-overload]


# ── reads (always safe) ──────────────────────────────────────────────────

@dataclass(frozen=True)
class ReadFile(Request):
    """Read a local file's text. The interpreter enforces path policy."""

    type: ClassVar[str] = "read_file"
    tier: ClassVar[str] = TIER_READ
    path: str
    encoding: str = "utf-8"


@dataclass(frozen=True)
class QueryDb(Request):
    """Run a read-only SQL query (SELECT/PRAGMA). Enforced by ``db.query``."""

    type: ClassVar[str] = "query_db"
    tier: ClassVar[str] = TIER_READ
    sql: str
    max_rows: int = 100


@dataclass(frozen=True)
class ListDir(Request):
    """Enumerate files under a root — the filesystem's ``getdents``.

    General-purpose by design: this is a *resource* access (what files exist),
    not an algorithm. Glob matching, filtering, and ranking are pure code that
    belongs in tools. The kernel walk is confined to the allowed read roots,
    prunes well-known junk directories, never follows links, and returns
    relative paths with size/mtime so tools can filter and sort without
    further requests."""

    type: ClassVar[str] = "list_dir"
    tier: ClassVar[str] = TIER_READ
    root: str = ""
    recursive: bool = True


@dataclass(frozen=True)
class ReadFiles(Request):
    """Read many files in one round trip — the batched ``read``.

    Exists so content-scanning tools (grep and its unbounded successors) pay
    O(1) round trips, not one per file. Each path is confined to the allowed
    read roots; binary and oversized files come back as per-file errors, not
    failures of the batch."""

    type: ClassVar[str] = "read_files"
    tier: ClassVar[str] = TIER_READ
    paths: list[str]
    max_bytes_per_file: int = 2_000_000


@dataclass(frozen=True)
class Stat(Request):
    """Metadata for one path: existence, kind, size, mtime."""

    type: ClassVar[str] = "stat"
    tier: ClassVar[str] = TIER_READ
    path: str


@dataclass(frozen=True)
class ReadContext(Request):
    """Read the tool's declared slice of the conversation.

    ``view`` mirrors the tool's declared view: ``full`` | ``last_k`` |
    ``params_only``. ``k`` applies to ``last_k``. The interpreter resolves this
    against the live conversation history; a ``params_only`` tool never gets
    conversation text at all.
    """

    type: ClassVar[str] = "read_context"
    tier: ClassVar[str] = TIER_READ
    view: str = "full"
    k: int | None = None


# ── writes (reversible; journalled) ──────────────────────────────────────

@dataclass(frozen=True)
class WriteFile(Request):
    """Write text to a local file. Journalled: undo restores prior bytes (or
    deletes the file if it did not exist)."""

    type: ClassVar[str] = "write_file"
    tier: ClassVar[str] = TIER_WRITE
    path: str
    content: str
    encoding: str = "utf-8"


@dataclass(frozen=True)
class WriteDb(Request):
    """Append rows to a task-owned table. ``schema_sql`` is the table's DDL,
    installed idempotently via ``db.ensure_output_table``. Journalled: undo
    deletes the rows this request inserted."""

    type: ClassVar[str] = "write_db"
    tier: ClassVar[str] = TIER_WRITE
    table: str
    schema_sql: str
    rows: list[dict[str, Any]]


@dataclass(frozen=True)
class DeleteFile(Request):
    """Delete a local file. Journalled: undo restores the prior bytes — a delete
    is reversible only because the kernel snapshots the file first. Root-confined
    to the write roots, exactly like ``WriteFile``; deleting a missing file is a
    successful no-op (``existed=False``)."""

    type: ClassVar[str] = "delete_file"
    tier: ClassVar[str] = TIER_WRITE
    path: str


@dataclass(frozen=True)
class Respond(Request):
    """The terminal request: the tool's final result. A well-formed tool run
    ends with exactly one ``Respond``. Carries the model-facing summary plus
    optional structured data and attachment paths (mapped onto ``ToolResult``).
    Tier ``read`` — returning a value is not an effect."""

    type: ClassVar[str] = "respond"
    tier: ClassVar[str] = TIER_READ
    summary: str = ""
    data: Any = None
    attachment_paths: list[str] | None = None
    success: bool = True
    error: str = ""


# ── egress (gated; exfiltration-capable regardless of verb) ──────────────

@dataclass(frozen=True)
class HttpRequest(Request):
    """An outbound HTTP call. Egress regardless of method — a GET's URL is a
    payload. Gated through the approval surface before it is placed."""

    type: ClassVar[str] = "http_request"
    tier: ClassVar[str] = TIER_EGRESS
    method: str
    url: str
    headers: dict[str, str] | None = None
    body: str | None = None
    timeout: float = 30.0


@dataclass(frozen=True)
class Complete(Request):
    """An LLM completion, served kernel-side by ``service_llm``. Egress: the
    prompt leaves the machine for a model endpoint, so it is exfiltration-
    capable. Keys and sockets stay in the kernel; the tool only names a prompt
    and an optional JSON schema for a structured reply."""

    type: ClassVar[str] = "complete"
    tier: ClassVar[str] = TIER_EGRESS
    prompt: str
    schema: dict[str, Any] | None = None
    system: str = ""


@dataclass(frozen=True)
class Embed(Request):
    """Embed text into vectors with the kernel's embedding model — the retrieval
    twin of ``Complete``. Egress: the text reaches a model the tool does not
    control (a hosted embedder, or a local model served kernel-side), so it is
    exfiltration-capable like any completion. Stored corpus vectors are ordinary
    db rows read via ``QueryDb``; only query-time embedding needs this."""

    type: ClassVar[str] = "embed"
    tier: ClassVar[str] = TIER_EGRESS
    inputs: list[str]
    model: str = ""


@dataclass(frozen=True)
class ExecSql(Request):
    """Execute a mutating SQL statement (UPDATE/DELETE/DDL/INSERT). Egress, not
    write: arbitrary DML is **not journalable**, and an effect the kernel cannot
    reverse is gated like any irreversible action (PRIMITIVES.md: irreversibility
    is the property, not the network). Read-only statements are refused — use
    ``QueryDb``. Gated through the approval surface."""

    type: ClassVar[str] = "exec_sql"
    tier: ClassVar[str] = TIER_EGRESS
    sql: str


@dataclass(frozen=True)
class RunProcess(Request):
    """Run a subprocess: the shell exposed as one mediated, gated verb. Egress
    and always gated — spawning a process is irreversible and boundary-crossing,
    and raw ``fork``/``exec`` is never handed to a tool (only this single verb,
    with the kernel owning the handle — the same exception that admits email and
    MCP transports). ``argv`` is a list, never a shell string (no shell parsing);
    ``cwd`` is confined to the allowed roots; output is captured and capped."""

    type: ClassVar[str] = "run_process"
    tier: ClassVar[str] = TIER_EGRESS
    argv: list[str]
    cwd: str = ""
    timeout: float = 60.0


# ── registry + wire helpers ──────────────────────────────────────────────

REQUEST_TYPES: dict[str, type[Request]] = {
    cls.type: cls
    for cls in (
        ReadFile, ReadFiles, ListDir, Stat, QueryDb, ReadContext,
        WriteFile, WriteDb, DeleteFile, Respond,
        HttpRequest, Complete, Embed, ExecSql, RunProcess,
    )
}


def request_class(type_tag: str) -> type[Request]:
    """Return the request class for a wire tag, or raise ``KeyError``."""
    return REQUEST_TYPES[type_tag]


def from_wire(payload: dict[str, Any]) -> Request:
    """Rebuild a ``Request`` from a ``to_wire()`` dict.

    Raises ``KeyError`` for an unknown tag and ``TypeError`` for missing/extra
    fields — both are the kernel's signal to hard-reject a malformed request
    coming off the pipe.
    """
    tag = payload.get("type")
    cls = REQUEST_TYPES.get(tag)
    if cls is None:
        raise KeyError(f"unknown request type: {tag!r}")
    field_names = {f.name for f in fields(cls)}
    kwargs = {k: v for k, v in payload.items() if k != "type"}
    unknown = set(kwargs) - field_names
    if unknown:
        raise TypeError(f"{tag}: unexpected fields {sorted(unknown)}")
    return cls(**kwargs)

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


@dataclass(frozen=True)
class ReadConversations(Request):
    """Read the caller's own conversations: list, categories, or one preview.

    Split out of ``ConversationOp`` rather than added as an action on it, on the
    same reasoning that separates ``QueryDb`` from ``ExecSql``: that verb mixes
    creating and *deleting* history with merely looking at it, and one tier
    cannot be right for both. Reading is read-tier; destroying is egress.

    Safe at read tier because ownership is enforced **kernel-side** on every
    row — the same argument-level authorization that confines ``ReadFile`` to the
    read roots. A caller sees its own conversations and no one else's, so this
    cannot become a cross-user leak the way an unfiltered ``QueryDb`` against the
    conversations table would.

    ``mode`` selects a shape, not a method:
    ``list`` (recent rows, optionally by category) · ``categories`` (distinct
    labels) · ``preview`` (one conversation's agent, notification mode, and last
    couple of turns). It stays a fixed set for the reason ``ReadContext``'s views
    do — a mode that took arbitrary arguments would be a generic dispatcher.
    """

    type: ClassVar[str] = "read_conversations"
    tier: ClassVar[str] = TIER_READ
    mode: str = "list"
    conversation_id: int | None = None
    category: str | None = None
    limit: int = 15


@dataclass(frozen=True)
class AskUser(Request):
    """Ask the human a question and wait for the answer.

    **Not egress**: the user is inside the trust domain, so showing them a
    prompt is not a boundary crossing and needs no approval — asking to be
    allowed to ask would be circular. It is read-tier because it mutates
    nothing the kernel owns; what comes back is untrusted input, exactly like
    file contents.

    It does gate on **attendance**, which is a liveness question rather than a
    permission one: an unattended session (a scheduled subagent, a background
    driver) has nobody to answer, so the request fails fast instead of hanging a
    turn forever. That check is `runtime.is_attended`, the kernel's single
    reader for "is a human present at this session right now?".

    ``choices`` renders as buttons where the frontend supports them and is
    advisory otherwise — the answer is always returned as text, because a
    frontend may not honour them and a plugin must not assume it did.
    """

    type: ClassVar[str] = "ask_user"
    tier: ClassVar[str] = TIER_READ
    prompt: str
    title: str = ""
    choices: list[str] | None = None


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
class ReloadPlugin(Request):
    """Load, reload, or unload the plugin at ``path`` — registry mutation as a
    mediated verb.

    The kernel's registries used to be mutated directly by whatever service felt
    like it (the hot-reloader, the package manager), with no audit trail. Routing
    it through a request means a reload is ledger-recorded, root-confined, and
    gated like anything else — *more* mediated than the in-process version it
    replaces, not less.

    **Egress tier, and this is the strict reading of the deferred-execution
    rule**: loading a plugin *executes code*, which is the one thing a write must
    never become. It is also not journalable — you cannot un-run a module's
    import side effects — so by the tier table it cannot be a write.

    What it actually costs is graded at fulfilment, the same way a bus emit is:
    the interpreter derives the danger from the declarations of the plugin being
    loaded, so reloading a read-only tool need not interrupt anyone while
    reloading an egress-tier one does.
    """

    type: ClassVar[str] = "reload_plugin"
    tier: ClassVar[str] = TIER_EGRESS
    path: str
    action: str = "reload"      # "reload" | "unload"



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


# ── administration (egress tier; principal-gated) ────────────────────────
#
# The kernel administers itself through slash commands, and those commands have
# to reach config, services, packages and conversations. Expressing that as
# requests is what lets kernel commands run on the same contract as everything
# else — but the same verb in an agent-authored tool would be a straight
# escalation (a config write can rewrite ``sandbox_write_roots`` itself).
#
# The resolution is that these four are ordinary **egress-tier** requests — they
# are irreversible or execute code, exactly like ``ExecSql`` and ``RunProcess`` —
# and that *who is asking* decides whether the gate passes, needs approval, or
# refuses. That policy lives in ``effects/declarations.py``; nothing about it is
# encoded here, because the tier is a property of the operation alone.
#
# Note there is deliberately no ``ReadConfig``: config holds API keys, and a read
# there composes with any egress into key theft (PRIMITIVES.md, Kernel state).
# ``WriteConfig`` must not become a read by returning the prior value.

@dataclass(frozen=True)
class WriteConfig(Request):
    """Set one config key. Irreversible in the sense that matters: the value it
    overwrites is not journalled, and config governs the confinement policy
    itself.

    ``scope`` names one of the three places config actually lives, which is the
    same three ``/config`` shows as storage locations:

    - ``global`` — the kernel config file, plus plugin_config.json when the key
      turns out to be plugin-declared.
    - ``plugin`` — plugin_config.json explicitly, for a key whose owning plugin
      is not installed *yet*. ``/setup`` needs this: it writes Telegram
      credentials before the Telegram frontend exists, so discovery cannot tell
      that the key is plugin-owned.
    - ``user`` — the current user's config blob, never the shared files.
    """

    type: ClassVar[str] = "write_config"
    tier: ClassVar[str] = TIER_EGRESS
    key: str
    value: Any = None
    scope: str = "global"


@dataclass(frozen=True)
class ServiceControl(Request):
    """Start, stop, or reload a service by name. Egress because loading executes
    module-level code and import side effects cannot be un-run — the same
    reasoning that puts ``ReloadPlugin`` at this tier."""

    type: ClassVar[str] = "service_control"
    tier: ClassVar[str] = TIER_EGRESS
    name: str
    action: str = "start"


@dataclass(frozen=True)
class PackageOp(Request):
    """Install or uninstall a store package by file stem. Egress twice over: it
    fetches from the network and it lands code the kernel will later execute."""

    type: ClassVar[str] = "package_op"
    tier: ClassVar[str] = TIER_EGRESS
    name: str
    action: str = "install"


@dataclass(frozen=True)
class TaskControl(Request):
    """Pause, unpause, reset, retry, or trigger a pipeline task.

    Egress rather than write, for two different reasons depending on the action,
    which is why they share one verb rather than splitting further: ``reset`` and
    ``retry`` discard processing state the journal never captured, and ``trigger``
    *runs* a task — the deferred-execution rule again.

    Unlike ``CallTool`` this does not borrow its tier from the target. It could,
    and the machinery exists — but ``/tasks`` is an administration command a human
    runs occasionally, not a hot path, so the principal policy already removes the
    friction (the user typing ``/tasks`` is the ``allow`` corner) without needing
    per-target derivation. ``CallTool`` earned that complexity by being the
    generic caller the agent uses constantly; this has not.
    """

    type: ClassVar[str] = "task_control"
    tier: ClassVar[str] = TIER_EGRESS
    name: str
    action: str = "pause"
    payload: dict[str, Any] | None = None


@dataclass(frozen=True)
class ReadConfig(Request):
    """Read one config value — the domain PRIMITIVES.md had to leave empty.

    The original objection stands and is not weakened: config holds API keys, and
    a read there composes with any egress into key theft. What changed is that
    "who is asking" is now expressible. The hazard was always specifically *an
    agent* reading config; a human running ``/config`` to see their own settings
    is not a threat to themselves, and the command has always displayed those
    values in plain text.

    So this is graded like the administration verbs rather than like an ordinary
    read: allowed outright for the user acting through reviewed code, gated in
    between, and **refused** for untrusted code in an agent turn — the corner
    where key theft would actually happen.

    It is egress tier for the same reason: what makes a config read dangerous is
    that it composes onward, and pretending otherwise by grading it ``read``
    would let it slip past every gate that matters.

    ``keys`` reads several at once and returns a dict — the ``ReadFiles`` to
    ``ReadFile``'s single read. ``/config`` lists dozens of settings with their
    values, and one round trip per setting would be absurd; batching also means
    one ledger row for one user action rather than forty.
    """

    type: ClassVar[str] = "read_config"
    tier: ClassVar[str] = TIER_EGRESS
    key: str = ""
    keys: list[str] | None = None
    scope: str = "global"


@dataclass(frozen=True)
class SessionAction(Request):
    """Act on the live conversation *session*: cancel, go back, skip a field.

    A separate verb from ``ConversationOp`` rather than an action on it, because
    they are different resources. A conversation is durable state with an owner;
    a session is the ephemeral in-flight interaction — cancelling a form changes
    no stored data and destroys no history. Folding them together would force one
    tier onto both, and would put ``cancel`` (trivially reversible: run the
    command again) behind the same gate as ``delete`` (irreversible).

    Egress rather than write only because the state machine's transitions are not
    journalled, so the kernel cannot offer to undo one. The principal policy is
    what keeps this from being friction: the user cancelling their own form is
    the ``allow`` corner.
    """

    type: ClassVar[str] = "session_action"
    tier: ClassVar[str] = TIER_EGRESS
    action: str
    payload: dict[str, Any] | None = None


@dataclass(frozen=True)
class CallTool(Request):
    """Invoke a registered tool by name.

    **This request's tier is not fixed — it is the called tool's tier.** Every
    other verb in this vocabulary names a resource whose danger is a property of
    the verb itself; this one names a *thing that has its own declarations*, so
    grading it by the verb would be meaningless. Calling ``read_file`` and
    calling ``run_process`` through the same wrapper are not the same act, and a
    fixed tier would either over-gate the first or under-gate the second.

    The class-level ``tier`` below is therefore only the floor used when the
    target cannot be resolved. ``effects/declarations.py::effective_tier``
    computes the real one, the same transitive move ``channel_danger_tier``
    already makes for bus emits: the danger of a thing that triggers other things
    is the maximum danger of what it triggers.

    A tool may not call itself, directly or through a cycle — the interpreter
    tracks the call chain and refuses, because a sandbox that can recurse without
    bound is a resource-exhaustion hole.
    """

    type: ClassVar[str] = "call_tool"
    tier: ClassVar[str] = TIER_EGRESS
    name: str
    params: dict[str, Any] | None = None


@dataclass(frozen=True)
class ConversationOp(Request):
    """Create, delete, load, clear, or recategorize a conversation. Egress:
    deleting or clearing destroys history that no journal can restore, and
    ownership is enforced kernel-side via ``runtime.assert_conversation_access``.

    Unlike ``SessionAction`` this touches durable, owned state — which is exactly
    why the two are separate verbs."""

    type: ClassVar[str] = "conversation_op"
    tier: ClassVar[str] = TIER_EGRESS
    action: str
    conversation_id: int | None = None
    fields: dict[str, Any] | None = None


# ── registry + wire helpers ──────────────────────────────────────────────

REQUEST_TYPES: dict[str, type[Request]] = {
    cls.type: cls
    for cls in (
        ReadFile, ReadFiles, ListDir, Stat, QueryDb, ReadContext, AskUser,
        ReadConversations,
        WriteFile, WriteDb, DeleteFile, Respond,
        HttpRequest, Complete, Embed, ExecSql, RunProcess, ReloadPlugin,
        WriteConfig, ReadConfig, ServiceControl, PackageOp, ConversationOp,
        SessionAction, CallTool, TaskControl,
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

"""The kernel-side interpreter: fulfil typed requests, mediate the boundary.

A pure tool yields a :class:`~effects.vocabulary.Request`; the interpreter
fulfils it against real resources (db, filesystem, llm, sockets) and hands back
an :class:`EffectResult`. The tool never touches those resources directly — this
module is the entire trusted rim.

Policy by tier:

- **read**  — executed directly.
- **write** — executed, then an undo entry is pushed onto the turn journal so
  the whole turn can be rolled back in reverse. A durable audit row is written
  to ``effect_journal``.
- **egress** — routed through the egress gate (the same approval surface the
  runtime already uses) *before* the call is placed. A denial is a normal,
  tool-visible outcome (``EffectResult.denied``), not a crash.

An **undeclared** request type is different from a denied one: it is a contract
violation and raises :class:`~effects.declarations.UndeclaredRequestError`,
which the runner turns into a failed tool run.

Every fulfilment is recorded to the action ledger (origin ``"effect"``),
best-effort — the ledger observes the system and must never break it.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from effects.declarations import (
    ADMIN_REQUESTS, ALLOW, PRINCIPAL_AGENT, REFUSE, admin_disposition,
    validate_declared,
)
from effects import fs_search
from effects.vocabulary import (
    TIER_EGRESS,
    TIER_READ,
    TIER_WRITE,
    AskUser,
    CallTool,
    Complete,
    ConversationOp,
    DeleteFile,
    Embed,
    ExecSql,
    HttpRequest,
    ListDir,
    PackageOp,
    QueryDb,
    ReadConfig,
    ReadContext,
    ReadConversations,
    ReadFile,
    ReadFiles,
    ReloadPlugin,
    Request,
    ScheduleOp,
    Respond,
    RunProcess,
    ServiceControl,
    SessionAction,
    Stat,
    TaskControl,
    WriteConfig,
    WriteDb,
    WriteFile,
)

logger = logging.getLogger("Effects")

_VALID_TABLE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_MAX_EGRESS_BYTES = 200_000

# Ambient *inventory* views: what plugins exist right now, as plain data.
#
# The introspection commands (/commands, /tools, /tasks, /services, /frontends,
# /debug) are the reason these exist. They read live kernel objects today -- the
# command registry, ``session.cs``, task instances -- which is exactly what a
# sandboxed body cannot hold, and it is why "it only reports, it does not mutate"
# turned out to be the wrong test for whether a command could cross.
#
# These are the same class as ``paths``: non-secret facts about the run, keyed by
# a fixed string, returning JSON-able data. The kernel walks its own registries
# and hands back names and static metadata; the plugin never touches an object.
#
# **This must stay a small closed set, not a dispatcher.** PRIMITIVES.md's rule
# is that ``ReadContext`` is a mode on a read primitive -- the moment a view takes
# arguments and reaches arbitrary kernel state, it has become ``CallRuntime(method,
# args)`` wearing a read badge, which the generality bar rejects. Adding a view
# means adding a name here and a branch in the provider, deliberately.
INVENTORY_VIEWS: frozenset[str] = frozenset({
    "commands", "tools", "tasks", "services", "frontends", "session_state",
    "packages", "pipeline", "settings", "llm_backends", "scheduled_jobs",
})

# Tables a sandboxed request may never touch, by identifier. ``users`` is the
# credential store (``password_hash``) and the per-user config blob; a read there
# is *read*-tier and ungated, and ``Complete``/``Embed`` are allowed by default,
# so the pair composes directly into credential exfiltration — precisely the
# hazard PRIMITIVES.md records for the kernel-state domain. Identity is available
# the safe way through ``ReadContext("user_id")``.
#
# Scanned as whole identifiers, which covers quoting, schema qualification, CTEs
# and subqueries alike (`"users"`, `main.users`, `FROM users u`) because the
# identifier still appears literally. Conservative by construction: a false
# positive refuses a query, never leaks one.
DENIED_SQL_IDENTIFIERS: frozenset[str] = frozenset({"users"})

# Leading keywords that mean "read only" — an ExecSql starting with one of these
# is refused (it belongs on QueryDb, which is ungated read tier). Comments and
# whitespace are stripped first.
_READ_ONLY_SQL = ("select", "pragma", "explain", "with")
_SQL_COMMENT = re.compile(r"^\s*(--[^\n]*\n|/\*.*?\*/)", re.DOTALL)


def _check_egress_url(raw: str) -> str:
    """Validate an outbound URL at the point of use. Raises ``PermissionError``.

    Scheme is the load-bearing check: ``HttpRequest`` is graded egress and gated
    accordingly, but a ``file://`` URL is not egress at all — it is a *local
    read* wearing an egress badge, and urllib will happily serve it, bypassing
    ``read_roots`` entirely. Only http/https reach the network, so only they are
    admitted; every other scheme (file, ftp, data, gopher) is refused outright.

    Also refused: credentials embedded in the URL (``user:pass@host`` leaks a
    secret into ledger rows and the approval dialog) and link-local addresses
    (169.254/16, notably the 169.254.169.254 cloud-metadata endpoint, which is
    an unauthenticated credential source reachable from any host). Broader
    private-network access stays *allowed but gated* — a human sees the target
    in the approval dialog, and local services are a legitimate use.
    """
    from urllib.parse import urlsplit

    try:
        parts = urlsplit((raw or "").strip())
    except ValueError as e:
        raise PermissionError(f"malformed url: {e}") from e
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise PermissionError(
            f"url scheme {scheme or '(none)'!r} is not permitted; "
            f"HttpRequest speaks http/https only (use ReadFile for local files)")
    if parts.username or parts.password:
        raise PermissionError("credentials embedded in a url are not permitted")
    host = (parts.hostname or "").strip()
    if not host:
        raise PermissionError("url has no host")
    if host.lower().startswith("169.254.") or host.lower() == "metadata.google.internal":
        raise PermissionError(f"link-local/metadata host {host!r} is not permitted")
    return raw


def _check_sql_tables(sql: str, denied: frozenset[str] | None) -> str:
    """Refuse SQL that references a denied table. Raises ``PermissionError``.

    Argument-level authorization for the database domain: the tier says *reads
    are safe*, which is true only of resources the tool is entitled to. Whether
    a given SELECT is entitled is a property of its arguments, not its verb, so
    it is decided here at the point of use."""
    if not denied:
        return sql
    for identifier in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", sql or ""):
        if identifier.lower() in denied:
            raise PermissionError(
                f"table {identifier!r} is not readable from a sandboxed request")
    return sql


def _is_read_only_sql(sql: str) -> bool:
    """True if ``sql``'s first keyword is read-only (SELECT/PRAGMA/EXPLAIN/WITH).

    Conservative by design: a mutating statement never starts with these, so a
    false negative is impossible; the point is only to send reads to QueryDb."""
    text = (sql or "").strip()
    while True:
        stripped = _SQL_COMMENT.sub("", text, count=1)
        if stripped == text:
            break
        text = stripped.strip()
    first = text.split(None, 1)[0].lower() if text else ""
    return first in _READ_ONLY_SQL


class EgressDenied(RuntimeError):
    """An egress request was refused by the gate. Available for callers that
    want to escalate a denial to a hard failure; the interpreter itself returns
    an :class:`EffectResult` with ``denied=True`` instead of raising."""


@dataclass
class EffectResult:
    """The interpreter's reply to one request."""

    ok: bool = True
    value: Any = None
    error: str = ""
    denied: bool = False       # egress refused by the gate
    tier: str = TIER_READ

    def to_wire(self) -> dict[str, Any]:
        """Serialize for the subprocess pipe."""
        return {
            "ok": self.ok,
            "value": self.value,
            "error": self.error,
            "denied": self.denied,
            "tier": self.tier,
        }


@dataclass
class _UndoEntry:
    """One reversible step recorded on the turn journal."""

    request_type: str
    undo: Callable[[], None]
    description: str = ""


class TurnJournal:
    """In-memory undo log for one turn's reversible writes.

    The undo unit is the turn: ``rollback()`` replays every recorded undo in
    reverse order. Undo closures are in-memory (they capture prior file bytes,
    inserted-row ranges, etc.), so a journal is bound to a live turn; the
    durable ``effect_journal`` rows are the cross-restart audit trail, not the
    rollback mechanism.
    """

    def __init__(self) -> None:
        """Initialize an empty journal."""
        self._entries: list[_UndoEntry] = []

    def __len__(self) -> int:
        """Number of reversible steps recorded."""
        return len(self._entries)

    def record(self, request_type: str, undo: Callable[[], None], description: str = "") -> None:
        """Push an undo step."""
        self._entries.append(_UndoEntry(request_type, undo, description))

    def rollback(self) -> list[str]:
        """Undo every recorded write in reverse. Returns a list of error
        strings for steps that failed to reverse (best-effort — a failure to
        undo one step never blocks the others)."""
        errors: list[str] = []
        while self._entries:
            entry = self._entries.pop()
            try:
                entry.undo()
            except Exception as e:  # noqa: BLE001 — best-effort rollback
                errors.append(f"{entry.request_type}: {e}")
                logger.warning("Turn rollback failed for %s: %s", entry.request_type, e)
        return errors

    def clear(self) -> None:
        """Discard the journal without undoing (the turn committed)."""
        self._entries.clear()


def default_egress_gate(request: Request) -> tuple[bool, str]:
    """Conservative default: allow kernel-served model calls, deny the rest.

    ``Complete`` and ``Embed`` are the kernel's own models (keys stay
    kernel-side), so they are allowed by default; boundary-crossing actions
    (raw ``HttpRequest``, ``ExecSql`` mutation, ``RunProcess``) are refused
    unless a real gate (the runtime's approval surface) overrides this. Returns
    ``(allowed, reason)``.
    """
    if isinstance(request, (Complete, Embed)):
        return True, ""
    return False, "this egress is denied by default; no approval gate is wired"


def describe_taint(taint: list[str], limit: int = 3) -> str:
    """A short human-readable note about what a run has already read.

    Shown in the approval dialog so the decision is informed: "allow this HTTP
    call" and "allow this HTTP call by a tool that just read your SSH key" are
    very different questions, and only the second one is the real one."""
    if not taint:
        return ""
    shown = ", ".join(taint[:limit])
    more = f" (+{len(taint) - limit} more)" if len(taint) > limit else ""
    return f"has already read: {shown}{more}"


@dataclass
class EffectContext:
    """Everything the interpreter needs to fulfil requests for one tool run."""

    db: Any = None
    llm: Any = None
    embedder: Any = None
    # Path policy. ``None`` roots mean "allow anywhere" (tests / trusted use);
    # otherwise a path must resolve under one of the listed roots.
    read_roots: list[Path] | None = None
    write_roots: list[Path] | None = None
    # The subset of write_roots a tool may write to WITHOUT approval (scratch,
    # sandbox plugins, memory, plus any the user configures). A write inside
    # write_roots but outside these is gated through ``egress_gate`` first.
    # ``None`` means "no write-approval policy" — every allowed write is silent
    # (trusted/test use, and the prior behavior).
    free_write_roots: list[Path] | None = None
    # Non-secret resolved locations a tool may ask for via ReadContext("paths")
    # (root, data, scratch, memory_root, …). Never config values or keys.
    paths: dict | None = None
    # Resolves a ReadContext(view, k) request to conversation text.
    context_provider: Callable[[str, int | None], str] | None = None
    # Table identifiers no SQL request may reference (see
    # DENIED_SQL_IDENTIFIERS). ``None`` disables the check entirely — reserved
    # for tests; production contexts should keep the default.
    denied_sql_identifiers: frozenset[str] | None = DENIED_SQL_IDENTIFIERS
    # Asks the human a question: (title, prompt, choices) -> answer text, or
    # None if they declined. ``None`` for the whole field means no attended
    # session is available, and an AskUser request fails fast rather than
    # hanging a turn on a question nobody will see.
    ask_user: Callable[[str, str, list[str]], str | None] | None = None
    # Loads/reloads/unloads a plugin: (path, action) -> summary dict. ``None``
    # means registry mutation is unavailable, and a ReloadPlugin request fails
    # rather than silently doing nothing.
    reload_plugin: Callable[[str, str], Any] | None = None
    # Carries out an administration request (WriteConfig, ServiceControl,
    # PackageOp, ConversationOp): (request) -> result value. Injected rather than
    # imported so the interpreter stays free of kernel wiring and every one of
    # these is testable without a live system. ``None`` means administration is
    # unavailable and such a request fails rather than silently doing nothing.
    administer: Callable[[Request], Any] | None = None
    # Mutates the kernel's scheduled-job table: (request) -> (value, undo). The
    # undo half is not optional — ScheduleOp is graded *write*, and a write tier
    # whose handler cannot reverse itself is the tier lying about what it is.
    # Separate from ``administer`` because scheduling is not administration —
    # see ScheduleOp's docstring — and because it must be reachable from the
    # ticker's context, which has no administration surface at all.
    schedule: Callable[[Request], Any] | None = None
    # Resolves an inventory view (see INVENTORY_VIEWS) to plain JSON-able data:
    # (view) -> list/dict. ``None`` means inventory is unavailable and such a
    # read fails rather than returning a misleading empty list.
    inventory: Callable[[str], Any] | None = None
    # Invokes a registered tool: (name, params) -> result payload. ``None``
    # means CallTool is unavailable.
    call_tool: Callable[[str, dict], Any] | None = None
    # The registered tools, by name — read *only* to derive a CallTool's tier
    # from its target (see declarations.tool_danger_tier). Never handed to a
    # plugin; the plugin names a tool, the kernel holds the objects.
    tools: dict | None = None
    # Names already on the call stack, so a tool cannot call itself into a loop.
    call_chain: tuple[str, ...] = ()
    # Acts on the live session (cancel/back/skip): (action, payload) -> result.
    session_action: Callable[[str, dict], Any] | None = None
    # Reads the caller's own conversations: (request) -> data. Ownership is
    # enforced inside, which is what makes this safe at read tier.
    read_conversations: Callable[[Request], Any] | None = None
    # ── who is asking ────────────────────────────────────────────────────
    # Derived from the *dispatch path*, never from the plugin's family: a slash
    # command is the user acting, a tool call in an agent turn is the agent
    # acting. A caller that invokes another plugin propagates this rather than
    # minting a fresh one, so a command/tool bridge cannot launder authority.
    # Defaults to ``agent`` — the restrictive side — so a context that forgets to
    # set it fails closed.
    principal: str = PRINCIPAL_AGENT
    # Whether the *body being run* is trusted by provenance. The second ceiling
    # on administration: an agent-authored plugin gets no silent admin pass even
    # when a human is the one invoking it. Defaults to False for the same
    # fail-closed reason.
    plugin_trusted: bool = False
    # Gate for egress requests: (request) -> (allowed, reason).
    egress_gate: Callable[[Request], tuple[bool, str]] = default_egress_gate
    # Local data this run has already read, as short human-readable labels.
    # Appended by the interpreter, read by the egress gate: it is what turns a
    # per-request check into a *compositional* one. Reading is safe and
    # transmitting is gated, but the pair is the actual exfiltration hazard, and
    # neither request looks dangerous alone. PRIMITIVES.md calls this
    # "taint-sink analysis done dynamically at one chokepoint"; this list is the
    # taint. Mutable and per-run by design.
    taint: list[str] = field(default_factory=list)
    # When True, kernel-served model calls (Complete/Embed) are also routed
    # through the gate once the run has read local data. Off by default: the
    # keys stay kernel-side and read+summarise is the common, wanted case, so
    # the default is visibility rather than friction. Turn it on to require an
    # explicit approval before local data reaches a model endpoint.
    gate_model_calls_after_read: bool = False
    # Identity for ledger rows.
    tool_name: str = "tool"
    session_key: str | None = None
    conversation_id: int | None = None
    user_id: int | None = None


class Interpreter:
    """Fulfils requests for one tool run, journalling writes and gating egress."""

    def __init__(self, ctx: EffectContext, declared: list[str], journal: TurnJournal | None = None):
        """Bind the interpreter to a context, the tool's declarations, and a
        (possibly shared) turn journal."""
        self.ctx = ctx
        self.declared = list(declared or [])
        self.journal = journal if journal is not None else TurnJournal()

    # ── entry point ──────────────────────────────────────────────────────

    def fulfill(self, request: Request) -> EffectResult:
        """Fulfil one request. Raises on an undeclared request type (a contract
        violation); returns an :class:`EffectResult` for everything else,
        including egress denials and handler failures."""
        validate_declared(self.ctx.tool_name, request, self.declared)
        started = time.perf_counter()
        refusal = self._check_principal(request)
        if refusal is not None:
            self._record(request, refusal, started)
            return refusal
        try:
            if request.tier == TIER_READ:
                result = self._fulfill_read(request)
            elif request.tier == TIER_WRITE:
                result = self._fulfill_write(request)
            elif request.tier == TIER_EGRESS:
                result = self._fulfill_egress(request)
            else:  # unreachable given the closed vocabulary
                result = EffectResult(ok=False, error=f"unknown tier {request.tier!r}", tier=request.tier)
        except Exception as e:  # noqa: BLE001 — handler failure is tool-visible, not fatal
            result = EffectResult(ok=False, error=str(e), tier=request.tier)
        self._note_taint(request, result)
        self._record(request, result, started)
        return result

    # ── who is asking ────────────────────────────────────────────────────

    def _check_principal(self, request: Request) -> EffectResult | None:
        """Apply the principal/provenance policy to administration requests.

        Returns ``None`` to let the request proceed, or a denial. This runs
        *before* the tier dispatch, so a refused administration request never
        reaches its handler — and note it does not replace the egress gate: a
        disposition of ``approve`` simply falls through to
        ``_fulfill_egress``, which asks the human as it would for any egress.
        The policy's job is only to decide whether "allow silently", "ask", or
        "never" applies.
        """
        # Recursion is refused *structurally*, before any policy runs. A
        # sandbox that can recurse without bound is a resource-exhaustion hole,
        # and that is true whether or not an approval gate happens to be wired —
        # checking it after the gate would let a denial mask the real reason.
        if isinstance(request, CallTool) and request.name in self.ctx.call_chain:
            chain = " -> ".join([*self.ctx.call_chain, request.name])
            return EffectResult(
                ok=False, denied=True, tier=request.tier,
                error=f"refusing recursive call to {request.name!r}: {chain}")

        if request.type not in ADMIN_REQUESTS:
            return None
        disposition = admin_disposition(self.ctx.principal, self.ctx.plugin_trusted)
        if disposition == REFUSE:
            return EffectResult(
                ok=False, denied=True, tier=request.tier,
                error=(f"{request.type} refused: an untrusted plugin may not administer "
                       "the kernel from an agent turn"))
        return None

    def _admin_allowed_without_prompt(self, request: Request) -> bool:
        """Whether this administration request needs no approval prompt.

        True only for the user acting through a trusted body: the human already
        expressed the intent by typing the command, so prompting again would be
        pure friction. Recomputed from the two context fields rather than
        remembered from ``_check_principal`` -- interpreter instances outlive a
        single request, and a remembered "already authorized" flag would leak
        that authorization onto every later request in the run.
        """
        return (request.type in ADMIN_REQUESTS
                and admin_disposition(self.ctx.principal, self.ctx.plugin_trusted) == ALLOW)

    def effective_tier(self, request: Request) -> str:
        """The tier this request should actually be graded at.

        Almost always the class-level tier: danger is a property of the operation
        and does not vary. ``CallTool`` is the exception, and deliberately so —
        it names a thing that carries its own declarations, so its danger is
        *borrowed* from the target rather than fixed by the wrapper. Grading it
        as a flat egress would gate a call to a read-only tool as though it
        posted to an API, which trains people to click through approvals."""
        if isinstance(request, CallTool):
            from effects.declarations import tool_danger_tier
            return tool_danger_tier(request.name, self.ctx.tools or {})
        return request.tier

    def _needs_gate(self, request: Request) -> bool:
        """Whether this egress-tier request must pass the approval surface.

        Two ways out. An administration request in the ``allow`` corner is the
        user acting through reviewed code, and the human already expressed the
        intent by typing the command. A ``CallTool`` whose target is not itself
        egress borrows that lower tier, so it is gated the way the target would
        have been — which is to say, by the target's own requests when it runs.
        """
        if self._admin_allowed_without_prompt(request):
            return False
        return self.effective_tier(request) == TIER_EGRESS

    # ── compositional tracking ───────────────────────────────────────────

    # Reads that bring *local data* into the plugin's hands. ReadContext is
    # excluded: the conversation is the plugin's own subject matter, and the
    # model already saw it. Respond is excluded: it is the terminal value, not
    # an acquisition.
    _TAINTING_READS = (ReadFile, ReadFiles, QueryDb, ListDir, Stat)

    def _note_taint(self, request: Request, result: EffectResult) -> None:
        """Record that this run has read local data.

        Reading is safe. Transmitting is gated. The *pair* is exfiltration, and
        neither request looks dangerous on its own — so the composition has to be
        tracked somewhere, and the interpreter is the one place every request
        passes through."""
        if not result.ok or not isinstance(request, self._TAINTING_READS):
            return
        label = (getattr(request, "path", None)
                 or getattr(request, "root", None)
                 or getattr(request, "sql", None)
                 or (", ".join(getattr(request, "paths", [])[:3]) or None)
                 or request.type)
        label = str(label)[:120]
        if label not in self.ctx.taint:
            self.ctx.taint.append(label)

    # ── reads ────────────────────────────────────────────────────────────

    def _fulfill_read(self, request: Request) -> EffectResult:
        """Handle read-tier requests."""
        if isinstance(request, ReadFile):
            path = self._check_path(request.path, write=False)
            text = path.read_text(encoding=request.encoding)
            return EffectResult(value=text, tier=TIER_READ)
        if isinstance(request, QueryDb):
            if self.ctx.db is None:
                return EffectResult(ok=False, error="no database available", tier=TIER_READ)
            _check_sql_tables(request.sql, self.ctx.denied_sql_identifiers)
            out = self.ctx.db.query(request.sql, max_rows=request.max_rows)
            return EffectResult(value=out, tier=TIER_READ)
        if isinstance(request, ListDir):
            out = fs_search.list_dir(request.root, self.ctx.read_roots, recursive=request.recursive)
            ok = "error" not in out
            return EffectResult(ok=ok, value=out, error=out.get("error", ""), tier=TIER_READ)
        if isinstance(request, ReadFiles):
            out = fs_search.read_files(
                request.paths, self.ctx.read_roots,
                max_bytes_per_file=request.max_bytes_per_file)
            return EffectResult(value=out, tier=TIER_READ)
        if isinstance(request, Stat):
            out = fs_search.stat_path(request.path, self.ctx.read_roots)
            ok = "error" not in out
            return EffectResult(ok=ok, value=out, error=out.get("error", ""), tier=TIER_READ)
        if isinstance(request, ReadContext):
            # Ambient, non-secret session facts resolve straight off the context
            # (no conversation text — a params_only tool may still learn where it
            # is and whose data it holds). Everything else is conversation text.
            view = request.view
            if view == "conversation_id":
                return EffectResult(value=self.ctx.conversation_id, tier=TIER_READ)
            if view == "user_id":
                return EffectResult(value=self.ctx.user_id, tier=TIER_READ)
            if view == "paths":
                return EffectResult(value=dict(self.ctx.paths or {}), tier=TIER_READ)
            if view in INVENTORY_VIEWS:
                if self.ctx.inventory is None:
                    return EffectResult(ok=False, tier=TIER_READ,
                                        error=f"no inventory provider for view {view!r}")
                return EffectResult(value=self.ctx.inventory(view), tier=TIER_READ)
            text = ""
            if self.ctx.context_provider is not None:
                text = self.ctx.context_provider(view, request.k)
            return EffectResult(value=text, tier=TIER_READ)
        if isinstance(request, ReadConversations):
            reader = self.ctx.read_conversations
            if reader is None:
                return EffectResult(ok=False, tier=TIER_READ,
                                    error="no conversation store is available")
            return EffectResult(value=reader(request), tier=TIER_READ)
        if isinstance(request, AskUser):
            asker = self.ctx.ask_user
            if asker is None:
                return EffectResult(
                    ok=False, tier=TIER_READ,
                    error="no attended session is available to answer a question")
            answer = asker(request.title or "Question", request.prompt,
                           list(request.choices or []))
            if answer is None:
                # Declining to answer is a normal outcome the plugin must handle,
                # not a failure of the run — same shape as an egress denial.
                return EffectResult(ok=False, denied=True, tier=TIER_READ,
                                    error="the user did not answer")
            return EffectResult(value=str(answer), tier=TIER_READ)
        if isinstance(request, Respond):
            # Terminal; the runner handles it, but fulfilling is harmless.
            return EffectResult(ok=request.success, value=request.to_wire(), error=request.error, tier=TIER_READ)
        return EffectResult(ok=False, error=f"unhandled read request {request.type!r}", tier=TIER_READ)

    # ── writes (journalled) ──────────────────────────────────────────────

    def _fulfill_write(self, request: Request) -> EffectResult:
        """Handle write-tier requests, pushing an undo entry onto the journal."""
        if isinstance(request, WriteFile):
            path = self._check_path(request.path, write=True)
            denial = self._gate_write(request, path)
            if denial is not None:
                return denial
            existed = path.exists()
            prior = path.read_bytes() if existed else None
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(request.content, encoding=request.encoding)

            def _undo() -> None:
                if prior is None:
                    if path.exists():
                        path.unlink()
                else:
                    path.write_bytes(prior)

            self.journal.record(request.type, _undo, f"write {path}")
            self._journal_row(request)
            return EffectResult(value={"path": str(path), "bytes": len(request.content)}, tier=TIER_WRITE)

        if isinstance(request, WriteDb):
            db = self.ctx.db
            if db is None:
                return EffectResult(ok=False, error="no database available", tier=TIER_WRITE)
            table = request.table
            if not _VALID_TABLE.match(table):
                return EffectResult(ok=False, error=f"invalid table name {table!r}", tier=TIER_WRITE)
            _check_sql_tables(table, self.ctx.denied_sql_identifiers)
            _check_sql_tables(request.schema_sql, self.ctx.denied_sql_identifiers)
            db.ensure_output_table(table, request.schema_sql)
            prev = db.query(f"SELECT COALESCE(MAX(rowid), 0) AS m FROM {table}")
            prev_max = prev["rows"][0][0] if prev["rows"] else 0
            db.write_outputs(table, request.rows)

            def _undo() -> None:
                db.execute_write(f"DELETE FROM {table} WHERE rowid > {int(prev_max)}")

            self.journal.record(request.type, _undo, f"insert {len(request.rows)} into {table}")
            self._journal_row(request)
            return EffectResult(value={"table": table, "inserted": len(request.rows)}, tier=TIER_WRITE)

        if isinstance(request, DeleteFile):
            path = self._check_path(request.path, write=True)
            denial = self._gate_write(request, path)
            if denial is not None:
                return denial
            existed = path.exists() and path.is_file()
            prior = path.read_bytes() if existed else None
            if existed:
                path.unlink()

            def _undo() -> None:
                if prior is not None:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(prior)

            self.journal.record(request.type, _undo, f"delete {path}")
            self._journal_row(request)
            return EffectResult(value={"path": str(path), "existed": existed}, tier=TIER_WRITE)

        if isinstance(request, ScheduleOp):
            scheduler = self.ctx.schedule
            if scheduler is None:
                return EffectResult(ok=False, tier=TIER_WRITE,
                                    error="no scheduled-job store is available")
            value, undo = scheduler(request)
            self.journal.record(request.type, undo,
                                f"{request.action} job {request.name or ''}".strip())
            self._journal_row(request)
            return EffectResult(value=value, tier=TIER_WRITE)

        return EffectResult(ok=False, error=f"unhandled write request {request.type!r}", tier=TIER_WRITE)

    # ── egress (gated) ───────────────────────────────────────────────────

    def _fulfill_egress(self, request: Request) -> EffectResult:
        """Gate, then place an egress request.

        ``Complete``/``Embed`` are normally served without a prompt because the
        keys stay kernel-side. But once this run has read local data, that
        reasoning stops covering the interesting case: the *prompt itself* is now
        carrying local content to a model endpoint. Whether that needs an
        approval is a policy call (``gate_model_calls_after_read``), off by
        default because read-then-summarise is the common wanted case — but the
        taint is always recorded, so the composition is visible in the ledger
        even when it is not gated."""
        if self._needs_gate(request):
            allowed, reason = self.ctx.egress_gate(request)
            if not allowed:
                return EffectResult(ok=False, denied=True, error=reason or "egress denied", tier=TIER_EGRESS)

        if isinstance(request, CallTool):
            caller = self.ctx.call_tool
            if caller is None:
                return EffectResult(ok=False, tier=TIER_EGRESS,
                                    error="no tool registry is available")
            return EffectResult(value=caller(request.name, dict(request.params or {})),
                                tier=TIER_EGRESS)

        if isinstance(request, SessionAction):
            act = self.ctx.session_action
            if act is None:
                return EffectResult(ok=False, tier=TIER_EGRESS,
                                    error="no active session to act on")
            return EffectResult(value=act(request.action, dict(request.payload or {})),
                                tier=TIER_EGRESS)

        if isinstance(request, (WriteConfig, ReadConfig, ServiceControl, PackageOp,
                                ConversationOp, TaskControl)):
            administer = self.ctx.administer
            if administer is None:
                return EffectResult(ok=False, tier=TIER_EGRESS,
                                    error=f"{request.type}: no administration surface is available")
            return EffectResult(value=administer(request), tier=TIER_EGRESS)

        if isinstance(request, HttpRequest):
            # Re-validated here, after the gate: the gate asks "may this leave?",
            # this asks "is this actually an outbound http call at all?".
            url = _check_egress_url(request.url)
            req = urllib.request.Request(
                url, method=request.method.upper(),
                headers=request.headers or {},
                data=request.body.encode("utf-8") if request.body else None,
            )
            with urllib.request.urlopen(req, timeout=request.timeout) as resp:  # noqa: S310 — gated egress
                raw = resp.read(_MAX_EGRESS_BYTES + 1)
                body = raw[:_MAX_EGRESS_BYTES].decode("utf-8", errors="replace")
                truncated = len(raw) > _MAX_EGRESS_BYTES
                return EffectResult(
                    value={"status": resp.status, "body": body, "truncated": truncated},
                    tier=TIER_EGRESS,
                )

        if isinstance(request, Complete):
            if self.ctx.llm is None:
                return EffectResult(ok=False, error="no llm service available", tier=TIER_EGRESS)
            messages = []
            if request.system:
                messages.append({"role": "system", "content": request.system})
            prompt = request.prompt
            if request.schema:
                prompt += (
                    "\n\nReply with ONLY a JSON object conforming to this schema:\n"
                    + json.dumps(request.schema)
                )
            messages.append({"role": "user", "content": prompt})
            resp = self.ctx.llm.invoke(messages)
            content = getattr(resp, "content", None)
            if getattr(resp, "is_error", False):
                return EffectResult(ok=False, error=getattr(resp, "error", "llm error"), tier=TIER_EGRESS)
            return EffectResult(value=content, tier=TIER_EGRESS)

        if isinstance(request, Embed):
            embedder = self.ctx.embedder
            if embedder is None:
                return EffectResult(ok=False, error="no embedder available", tier=TIER_EGRESS)
            vecs = embedder.encode(list(request.inputs))
            out = [[float(x) for x in vec] for vec in vecs]
            model = getattr(embedder, "model_name", "") or request.model
            return EffectResult(value={"vectors": out, "model": model}, tier=TIER_EGRESS)

        if isinstance(request, ExecSql):
            db = self.ctx.db
            if db is None:
                return EffectResult(ok=False, error="no database available", tier=TIER_EGRESS)
            if _is_read_only_sql(request.sql):
                return EffectResult(
                    ok=False, tier=TIER_EGRESS,
                    error="ExecSql is for mutations; use QueryDb for SELECT/PRAGMA/EXPLAIN")
            _check_sql_tables(request.sql, self.ctx.denied_sql_identifiers)
            result = db.execute_write(request.sql)
            rowcount = result if isinstance(result, int) else getattr(result, "rowcount", None)
            return EffectResult(value={"rowcount": rowcount}, tier=TIER_EGRESS)

        if isinstance(request, ReloadPlugin):
            reloader = self.ctx.reload_plugin
            if reloader is None:
                return EffectResult(ok=False, tier=TIER_EGRESS,
                                    error="no plugin loader is available")
            try:
                path = self._check_path(request.path, write=False)
            except PermissionError as e:
                return EffectResult(ok=False, tier=TIER_EGRESS, error=str(e))
            result = reloader(str(path), request.action)
            return EffectResult(value=result, tier=TIER_EGRESS)

        if isinstance(request, RunProcess):
            return self._run_process(request)

        return EffectResult(ok=False, error=f"unhandled egress request {request.type!r}", tier=TIER_EGRESS)

    def _run_process(self, request: RunProcess) -> EffectResult:
        """Spawn a subprocess (argv only, no shell), cwd-confined and capped.

        Every failure — bad argv, cwd outside the roots, timeout, spawn error —
        is a tool-visible EffectResult, never a raised exception."""
        argv = list(request.argv or [])
        if not argv or not all(isinstance(a, str) for a in argv):
            return EffectResult(ok=False, error="argv must be a non-empty list of strings", tier=TIER_EGRESS)
        cwd = None
        if request.cwd:
            try:
                cwd = str(self._check_path(request.cwd, write=False))
            except PermissionError as e:
                return EffectResult(ok=False, error=str(e), tier=TIER_EGRESS)
        elif self.ctx.read_roots:
            cwd = str(Path(self.ctx.read_roots[0]).expanduser().resolve())
        started = time.perf_counter()
        try:
            proc = subprocess.run(
                argv, cwd=cwd, capture_output=True, text=True, shell=False,
                timeout=max(1.0, float(request.timeout)),
            )
        except subprocess.TimeoutExpired:
            return EffectResult(ok=False, error=f"process timed out after {request.timeout}s", tier=TIER_EGRESS)
        except (OSError, ValueError) as e:
            return EffectResult(ok=False, error=f"could not run process: {e}", tier=TIER_EGRESS)
        out = (proc.stdout or "")[:_MAX_EGRESS_BYTES]
        err = (proc.stderr or "")[:_MAX_EGRESS_BYTES]
        truncated = len(proc.stdout or "") > _MAX_EGRESS_BYTES or len(proc.stderr or "") > _MAX_EGRESS_BYTES
        return EffectResult(value={
            "exit_code": proc.returncode, "stdout": out, "stderr": err,
            "truncated": truncated, "duration": round(time.perf_counter() - started, 3),
        }, tier=TIER_EGRESS)

    # ── helpers ──────────────────────────────────────────────────────────

    def _check_path(self, raw: str, *, write: bool) -> Path:
        """Resolve ``raw`` and enforce the read/write root policy.

        A relative path resolves against the first allowed root (the project
        root by convention), matching how ``fs_search`` resolves ListDir/Stat/
        ReadFiles — so "relative to the project root" means the same thing across
        every filesystem request."""
        roots = self.ctx.write_roots if write else self.ctx.read_roots
        p = Path(raw).expanduser()
        if not p.is_absolute() and roots:
            p = Path(roots[0]).expanduser().resolve() / p
        path = p.resolve()
        if roots is None:
            return path
        for root in roots:
            try:
                path.relative_to(Path(root).expanduser().resolve())
                return path
            except ValueError:
                continue
        verb = "write" if write else "read"
        raise PermissionError(f"path {path} is outside the allowed {verb} roots")

    def _gate_write(self, request: Request, path: Path) -> "EffectResult | None":
        """Approve a filesystem write that lands outside the free write roots.

        Sandbox/scratch (and any user-configured free root) are frictionless —
        low-consequence drafting space. A write anywhere else in the allowed
        roots (source files, config) is reversible but consequential, so it is
        routed through the approval gate first, exactly like an egress request.
        Returns a denial ``EffectResult`` if refused, else ``None`` to proceed."""
        free = self.ctx.free_write_roots
        if free is None:
            return None  # no policy wired: every allowed write is silent
        for root in free:
            try:
                path.relative_to(Path(root).expanduser().resolve())
                return None  # inside a free root — no approval needed
            except ValueError:
                continue
        allowed, reason = self.ctx.egress_gate(request)
        if not allowed:
            return EffectResult(ok=False, denied=True,
                                error=reason or "write denied by user", tier=TIER_WRITE)
        return None

    def _journal_row(self, request: Request) -> None:
        """Write a durable audit row to ``effect_journal`` (best-effort)."""
        db = self.ctx.db
        if db is None or not hasattr(db, "record_effect_journal"):
            return
        try:
            db.record_effect_journal(
                session_key=self.ctx.session_key,
                conversation_id=self.ctx.conversation_id,
                tool_name=self.ctx.tool_name,
                request=request.to_wire(),
            )
        except Exception as e:  # noqa: BLE001 — journal must never break a turn
            logger.debug("effect_journal write failed (ignored): %s", e)

    def _record(self, request: Request, result: EffectResult, started: float) -> None:
        """Append one fulfilment to the action ledger (best-effort)."""
        db = self.ctx.db
        if db is None or not hasattr(db, "record_action"):
            return
        db.record_action(
            origin="effect",
            action_type=request.type,
            ok=result.ok,
            session_key=self.ctx.session_key,
            conversation_id=self.ctx.conversation_id,
            user_id=self.ctx.user_id,
            actor_id=self.ctx.tool_name,
            name=request.type,
            args=request.to_wire(),
            error_message=result.error or None,
            error_code="denied" if result.denied else None,
            duration_ms=int((time.perf_counter() - started) * 1000),
            data={"tier": request.tier},
        )

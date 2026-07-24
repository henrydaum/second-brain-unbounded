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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from effects.declarations import validate_declared
from effects import fs_search
from effects.vocabulary import (
    TIER_EGRESS,
    TIER_READ,
    TIER_WRITE,
    Complete,
    DeleteFile,
    Embed,
    ExecSql,
    HttpRequest,
    ListDir,
    QueryDb,
    ReadContext,
    ReadFile,
    ReadFiles,
    Request,
    Respond,
    RunProcess,
    Stat,
    WriteDb,
    WriteFile,
)

logger = logging.getLogger("Effects")

_VALID_TABLE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_MAX_EGRESS_BYTES = 200_000

# Leading keywords that mean "read only" — an ExecSql starting with one of these
# is refused (it belongs on QueryDb, which is ungated read tier). Comments and
# whitespace are stripped first.
_READ_ONLY_SQL = ("select", "pragma", "explain", "with")
_SQL_COMMENT = re.compile(r"^\s*(--[^\n]*\n|/\*.*?\*/)", re.DOTALL)


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
    # Non-secret resolved locations a tool may ask for via ReadContext("paths")
    # (root, data, scratch, memory_root, …). Never config values or keys.
    paths: dict | None = None
    # Resolves a ReadContext(view, k) request to conversation text.
    context_provider: Callable[[str, int | None], str] | None = None
    # Gate for egress requests: (request) -> (allowed, reason).
    egress_gate: Callable[[Request], tuple[bool, str]] = default_egress_gate
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
        self._record(request, result, started)
        return result

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
            text = ""
            if self.ctx.context_provider is not None:
                text = self.ctx.context_provider(view, request.k)
            return EffectResult(value=text, tier=TIER_READ)
        if isinstance(request, Respond):
            # Terminal; the runner handles it, but fulfilling is harmless.
            return EffectResult(ok=request.success, value=request.to_wire(), error=request.error, tier=TIER_READ)
        return EffectResult(ok=False, error=f"unhandled read request {request.type!r}", tier=TIER_READ)

    # ── writes (journalled) ──────────────────────────────────────────────

    def _fulfill_write(self, request: Request) -> EffectResult:
        """Handle write-tier requests, pushing an undo entry onto the journal."""
        if isinstance(request, WriteFile):
            path = self._check_path(request.path, write=True)
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

        return EffectResult(ok=False, error=f"unhandled write request {request.type!r}", tier=TIER_WRITE)

    # ── egress (gated) ───────────────────────────────────────────────────

    def _fulfill_egress(self, request: Request) -> EffectResult:
        """Gate, then place an egress request."""
        allowed, reason = self.ctx.egress_gate(request)
        if not allowed:
            return EffectResult(ok=False, denied=True, error=reason or "egress denied", tier=TIER_EGRESS)

        if isinstance(request, HttpRequest):
            req = urllib.request.Request(
                request.url, method=request.method.upper(),
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
            result = db.execute_write(request.sql)
            rowcount = result if isinstance(result, int) else getattr(result, "rowcount", None)
            return EffectResult(value={"rowcount": rowcount}, tier=TIER_EGRESS)

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

"""The sandboxed-tool contract and its registry adapter.

A sandboxed tool is one self-contained artifact:

- ``name`` / ``description`` — the catalog line search_tools ranks.
- ``parameters`` — the fill schema (JSON Schema) presented at the forced fill.
- ``fill_prompt`` — guidance shown ONLY at fill time (not in the static system
  prompt), so an unbounded catalog costs nothing per turn.
- ``declared_requests`` — the effect request types it may issue; its danger tier
  is *derived* from these (never asserted), and an undeclared request at runtime
  is a hard reject.
- ``view`` — how much conversation it may read (``full`` / ``last_k`` /
  ``params_only``): the narrower the view, the cheaper the fill and the smaller
  the trust surface.
- ``run(self, params)`` — a **generator**: it yields effect requests
  (``effects.vocabulary``) and receives their fulfilments, ending by returning or
  yielding a ``Respond``. It never touches a db, socket, or file directly.

Discovery wraps each subclass in :class:`SandboxToolAdapter`, a thin ``BaseTool``
that ships the job to ``sandbox.runner`` — so from the ToolRegistry, the state
machine, ``_absorb``, and the ledger's point of view a sandboxed tool is
indistinguishable from an in-process one.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from effects.declarations import derive_tier
from effects.vocabulary import REQUEST_TYPES
from plugins.BaseTool import BaseTool, ToolResult

logger = logging.getLogger("SandboxTool")


class BaseSandboxTool:
    """The contract every sandboxed tool implements."""

    # --- Identity / catalog ---
    name: str = ""
    description: str = ""
    parameters: dict = {}
    fill_prompt: str = ""

    # --- Capability declaration (danger tier is derived from this) ---
    declared_requests: list[str] = []

    # --- Context view ---
    view: str = "params_only"   # "full" | "last_k" | "params_only"
    view_k: int = 6

    # --- Agent controls (mirrors BaseTool) ---
    max_calls: int = 5
    background_safe: bool = True

    # --- Store-package metadata parity (read by the package manager via AST) ---
    dependencies_files: list[str] = []
    dependencies_pip: list[str] = []

    # --- Sandbox resource limits (per tool; enforced by the runner) ---
    # timeout_s meters the CHILD's own compute wall-clock (the clock stops
    # while a request sits kernel-side, e.g. on an approval dialog).
    # memory_mb is enforced by the parent's psutil watchdog everywhere, plus
    # RLIMIT_AS belt-and-braces on Linux. cpu_seconds sets RLIMIT_CPU on
    # POSIX; on Windows the metered wall-clock timeout is the practical bound.
    timeout_s: float = 30.0
    memory_mb: int = 512
    cpu_seconds: int = 30

    def __init_subclass__(cls, **kwargs):
        """Validate declarations at definition time and copy mutable defaults."""
        super().__init_subclass__(**kwargs)
        for attr in ("parameters", "declared_requests", "dependencies_files", "dependencies_pip"):
            value = getattr(cls, attr)
            if isinstance(value, (dict, list)):
                setattr(cls, attr, value.copy())
        unknown = [t for t in cls.declared_requests if t not in REQUEST_TYPES]
        if unknown:
            raise TypeError(
                f"{cls.__name__}: unknown declared_requests {unknown}; "
                f"valid types are {sorted(REQUEST_TYPES)}"
            )
        if cls.view not in {"full", "last_k", "params_only"}:
            raise TypeError(f"{cls.__name__}: view must be full|last_k|params_only, got {cls.view!r}")

    @property
    def danger_tier(self) -> str:
        """The tool's danger tier: the max tier across declared_requests."""
        return derive_tier(self.declared_requests)

    def run(self, params: dict):
        """The tool body: a generator yielding effect requests, ending in a
        ``Respond``. Never fulfils a request itself."""
        raise NotImplementedError(f"Sandbox tool '{self.name}' must implement run()")


class SandboxToolAdapter(BaseTool):
    """Presents a :class:`BaseSandboxTool` to the ToolRegistry as a normal tool.

    Instantiated by discovery with the concrete sandbox class + its source path
    (so ``auto_register`` is False — it is never picked up as a bare BaseTool).
    Its ``run`` builds an :class:`~effects.interpreter.EffectContext` from the
    live runtime context and hands the job to ``sandbox.runner``.
    """

    auto_register = False

    def __init__(self, sandbox_cls: type[BaseSandboxTool], source_path: str):
        """Wrap a sandbox tool class and cache its source."""
        self._sandbox = sandbox_cls()
        self._sandbox_cls = sandbox_cls
        self.name = self._sandbox.name
        self.description = self._sandbox.description
        self.parameters = self._sandbox.parameters
        self.fill_prompt = self._sandbox.fill_prompt
        self.max_calls = self._sandbox.max_calls
        self.background_safe = self._sandbox.background_safe
        self.declared_requests = list(self._sandbox.declared_requests)
        self.danger_tier = self._sandbox.danger_tier
        self._source_path = source_path
        try:
            self._source = Path(source_path).read_text(encoding="utf-8")
        except OSError as e:
            logger.error("Could not read sandbox tool source %s: %s", source_path, e)
            self._source = ""

    def run(self, context, **kwargs) -> ToolResult:
        """Ship the fill job to the sandbox runner and map the outcome."""
        from sandbox.runner import run_sandbox_tool
        from effects.interpreter import EffectContext

        ectx = EffectContext(
            db=context.db,
            llm=(context.services or {}).get("llm"),
            embedder=(context.services or {}).get("text_embedder"),
            read_roots=self._read_roots(context),
            write_roots=self._write_roots(context),
            free_write_roots=self._free_write_roots(context),
            paths=self._paths(context),
            context_provider=self._context_provider(context),
            egress_gate=self._egress_gate(context),
            tool_name=self.name,
            session_key=context.session_key,
            conversation_id=self._conversation_id(context),
            user_id=context.user_id,
        )
        outcome = run_sandbox_tool(
            source=self._source,
            params=kwargs,
            declared=self.declared_requests,
            effect_ctx=ectx,
            timeout=float(context.config.get("tool_timeout", self._sandbox.timeout_s)),
            memory_mb=self._sandbox.memory_mb,
            cpu_seconds=self._sandbox.cpu_seconds,
        )
        return ToolResult(
            success=outcome.success,
            error=outcome.error,
            data=outcome.data,
            llm_summary=outcome.summary,
            attachment_paths=outcome.attachment_paths,
        )

    # ── effect-context wiring ────────────────────────────────────────────

    def _read_roots(self, context):
        """Roots the tool may read under. Defaults to repo root + DATA_DIR, with
        the project root first so a relative path resolves against it."""
        from paths import DATA_DIR
        roots = context.config.get("sandbox_read_roots")
        if roots:
            return [Path(r) for r in roots]
        base = []
        if context.root_dir:
            base.append(Path(context.root_dir))
        base.append(DATA_DIR)
        return base

    def _write_roots(self, context):
        """Outer confinement: where a write is permitted at all (outside → hard
        reject). Defaults to the project root + DATA_DIR; whether a given write
        needs approval is a separate question — see ``_free_write_roots``."""
        from paths import DATA_DIR
        roots = context.config.get("sandbox_write_roots")
        if roots:
            return [Path(r) for r in roots]
        base = []
        if context.root_dir:
            base.append(Path(context.root_dir))
        base.append(DATA_DIR)
        return base

    def _free_write_roots(self, context):
        """The subset of write roots that need NO approval — frictionless drafting
        space. Scratch, the sandbox-plugin tree, and the user's memory folder are
        always free; more can be added via the ``sandbox_free_write_roots`` config
        list (e.g. a synced directory the user trusts)."""
        from paths import SANDBOX_PLUGINS, SCRATCH_DIR
        free = [SCRATCH_DIR, SANDBOX_PLUGINS]
        try:
            from plugins.helpers.memory_paths import memory_root
            free.append(memory_root(context.user_id))
        except Exception:  # noqa: BLE001 — memory package may be absent
            pass
        for extra in (context.config.get("sandbox_free_write_roots") or []):
            free.append(Path(extra))
        return free

    def _paths(self, context):
        """Non-secret resolved locations a tool may read via ReadContext("paths").

        Only *where things are* — never config values or keys. Tools that write
        to per-user data (memory) or read a curated corpus (skills) resolve their
        root here instead of guessing paths."""
        from paths import DATA_DIR
        out = {"data": str(DATA_DIR), "scratch": str(DATA_DIR / "sandbox_scratch")}
        if context.root_dir:
            out["root"] = str(Path(context.root_dir))
        try:
            from plugins.helpers.memory_paths import memory_root
            out["memory_root"] = str(memory_root(context.user_id))
        except Exception:  # noqa: BLE001 — memory package may be absent; omit the key
            pass
        try:
            from plugins.helpers.plugin_paths import PLUGIN_ROOTS
            roots = [str(r.path / "skills") for r in PLUGIN_ROOTS
                     if (r.path / "skills").is_dir()]
            if roots:
                out["skills_roots"] = roots
        except Exception:  # noqa: BLE001 — skills package may be absent; omit the key
            pass
        return out

    def _conversation_id(self, context):
        """The current conversation id, via the live session if present."""
        session = self._session(context)
        return getattr(session, "conversation_id", None) if session else None

    def _session(self, context):
        """The live RuntimeSession, if reachable."""
        runtime = context.runtime
        if runtime is None or not context.session_key:
            return None
        return (getattr(runtime, "sessions", {}) or {}).get(context.session_key)

    def _context_provider(self, context):
        """Resolve the tool's declared view against the conversation history."""
        session = self._session(context)

        def provider(view: str, k: int | None) -> str:
            if view == "params_only":
                return ""
            history = list(getattr(session, "history", []) or [])
            if view == "last_k":
                history = history[-(k or self._sandbox.view_k):]
            return json.dumps(history, default=str)

        return provider

    def _egress_gate(self, context):
        """Kernel-served model calls (complete, embed) pass; boundary-crossing
        actions (HTTP, SQL mutation, subprocess) route through the approval
        surface, each with a legible target."""
        def gate(request):
            if request.type in ("complete", "embed"):
                return True, ""
            approve = context.approve_command
            if approve is None:
                return False, "no approval surface available for egress"
            ok = approve(_egress_target(request), f"sandboxed tool '{self.name}' {request.type}")
            return ok, "" if ok else (context.approval_denial_reason or "egress denied by user")

        return gate


def _egress_target(request) -> str:
    """A one-line, human-legible description of an egress request for approval."""
    if request.type == "http_request":
        return f"{getattr(request, 'method', '')} {getattr(request, 'url', '')}".strip()
    if request.type == "exec_sql":
        return getattr(request, "sql", "")
    if request.type == "run_process":
        return " ".join(getattr(request, "argv", []) or [])
    if request.type in ("write_file", "delete_file"):
        verb = "delete" if request.type == "delete_file" else "write"
        return f"{verb} {getattr(request, 'path', '')}"
    return request.type


def build_sandbox_adapters(module, module_name: str, source_path: str) -> list[SandboxToolAdapter]:
    """Find BaseSandboxTool subclasses declared in ``module`` and wrap each."""
    import inspect

    adapters = []
    for _, cls in inspect.getmembers(module, inspect.isclass):
        if (issubclass(cls, BaseSandboxTool) and cls is not BaseSandboxTool
                and cls.__module__ == module_name):
            try:
                adapters.append(SandboxToolAdapter(cls, source_path))
            except Exception as e:  # noqa: BLE001
                logger.error("Could not adapt sandbox tool %s: %s", cls.__name__, e, exc_info=True)
    return adapters

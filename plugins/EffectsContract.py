"""The effects contract, shared by every plugin family.

One mixin, mixed into ``BaseTool``, ``BaseCommand``, and (as they convert)
``BaseTask``, ``BaseService``, ``BaseFrontend``. It carries everything a plugin
needs to be a pure body over typed requests:

- the capability declaration (``declared_requests``) and the *derived*
  ``danger_tier``,
- the sandbox resource limits,
- the provenance check that picks an execution mode (``trusted``),
- the wiring that turns a live ``SecondBrainContext`` into an ``EffectContext``,
- ``_perform_effects``, which hands a body to whichever executor applies.

Families differ only in **what they call and what they do with the answer** — a
tool maps the outcome onto a ``ToolResult``, a command onto a markdown string, a
task onto ``TaskResult`` rows. None of them re-implements the boundary, which is
the point: there is exactly one place where a plugin body meets the kernel.

Nothing here is family-specific, and nothing here decides policy. Confinement
lives in ``EffectContext``; the tier table lives in ``effects/vocabulary.py``;
the admission rules live in ``effects/PRIMITIVES.md``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger("EffectsContract")


def egress_target(request) -> str:
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


class EffectsContract:
    """Mixin: makes a plugin class runnable as a pure body over typed requests."""

    # --- Execution contract ---
    # "effects" — the body is a generator yielding typed requests.
    # "legacy"  — the family's historical imperative signature (being migrated out).
    contract: str = "legacy"

    # --- Capability declaration (``contract = "effects"`` only) ---
    # The request types this plugin may issue. Its danger tier is *derived* from
    # these (never author-asserted); an undeclared request at runtime is a hard
    # reject.
    declared_requests: list[str] = []

    # How much conversation the body may read: "full" | "last_k" | "params_only".
    view: str = "params_only"
    view_k: int = 6

    # --- Sandbox resource limits (untrusted mode only) ---
    timeout_s: float = 30.0
    memory_mb: int = 512
    cpu_seconds: int = 30

    # ── declaration validation ───────────────────────────────────────────

    @classmethod
    def validate_effects_declaration(cls) -> None:
        """Check declarations at class-definition time, so a typo surfaces at
        import rather than as a silent capability gap. Called from each family's
        ``__init_subclass__``."""
        if cls.contract == "effects":
            from effects.vocabulary import REQUEST_TYPES
            unknown = [t for t in cls.declared_requests if t not in REQUEST_TYPES]
            if unknown:
                raise TypeError(
                    f"{cls.__name__}: unknown declared_requests {unknown}; "
                    f"valid types are {sorted(REQUEST_TYPES)}")
            if cls.view not in {"full", "last_k", "params_only"}:
                raise TypeError(
                    f"{cls.__name__}: view must be full|last_k|params_only, got {cls.view!r}")
        elif cls.declared_requests:
            raise TypeError(
                f'{cls.__name__}: declared_requests is only meaningful with contract = "effects"')

    @property
    def danger_tier(self) -> str:
        """Max tier across ``declared_requests`` — derived, never asserted."""
        from effects.declarations import derive_tier
        return derive_tier(self.declared_requests)

    # ── execution ────────────────────────────────────────────────────────

    def trusted(self, context) -> bool:
        """Whether this plugin runs in-process. Provenance only — never a config
        flag, and never anything the plugin asserts about itself.

        ``sandbox_trust_all`` forces trusted mode globally. It exists for the
        migration's all-trusted equivalence check and for debugging, not as a
        deployment mode; it is deliberately blunt so it cannot quietly become
        per-plugin policy."""
        from plugins.helpers.plugin_paths import is_trusted

        if (getattr(context, "config", None) or {}).get("sandbox_trust_all"):
            return True
        return is_trusted(getattr(self, "_source_path", ""))

    # Periodic work, without a thread of the plugin's own. A service declaring
    # tick_interval_s > 0 has its ``tick`` body called by the kernel's single
    # clock thread (runtime/service_ticker.py). ``tick`` returns the events it
    # wants fired -- it never touches the bus -- and the kernel fires only
    # channels listed in ``declared_channels``. That is the authority check:
    # declaring a channel is to the bus what declaring a request type is to the
    # interpreter.
    tick_interval_s: float = 0.0
    declared_channels: list[str] = []

    # Whether this plugin's sandbox should stay open between calls. False for
    # tools/commands/tasks — each call is complete in itself, and a fresh child
    # is the stronger isolation. Services override it to True: their state,
    # caches and background threads are the capability, so the child persists
    # for the service's lifetime.
    persistent_sandbox: bool = False

    def _perform_effects(self, context, params: dict, *, method: str = "run"):
        """Run one body through the applicable executor. Returns a
        ``SandboxOutcome``; the family maps it onto its own result type.

        Every path drives the same generator through the same interpreter, so
        what changes is only *where* the body runs and *how long that place
        lives* — never what the body may do."""
        ectx = self.build_effect_context(context)
        timeout = float((getattr(context, "config", None) or {})
                        .get("tool_timeout", self.timeout_s))
        if self.trusted(context):
            from sandbox.local import run_local_tool
            return run_local_tool(
                instance=self, params=params, declared=self.declared_requests,
                effect_ctx=ectx, method=method)
        if self.persistent_sandbox:
            from sandbox.worker import POOL
            worker = POOL.acquire(
                source=self._source_text(), memory_mb=self.memory_mb,
                cpu_seconds=self.cpu_seconds, persistent=True)
            return worker.call(
                params=params, declared=self.declared_requests, effect_ctx=ectx,
                method=method, timeout=timeout)
        from sandbox.runner import run_sandbox_tool
        return run_sandbox_tool(
            source=self._source_text(), params=params,
            declared=self.declared_requests, effect_ctx=ectx, method=method,
            timeout=timeout, memory_mb=self.memory_mb, cpu_seconds=self.cpu_seconds)

    def release_sandbox(self) -> None:
        """Close this plugin's resident worker, if it has one (a service's
        unload path). Safe to call when there is none."""
        if not self.persistent_sandbox or self.contract != "effects":
            return
        try:
            from sandbox.worker import POOL
            POOL.release(self._source_text())
        except Exception:  # noqa: BLE001 — teardown must not raise
            logger.debug("releasing sandbox worker failed", exc_info=True)

    def _source_text(self) -> str:
        """The plugin's own source, read lazily and cached. Only the untrusted
        path needs it (the child is fed source, not an object)."""
        cached = getattr(self, "_source_cache", None)
        if cached is not None:
            return cached
        try:
            text = Path(getattr(self, "_source_path", "")).read_text(encoding="utf-8")
        except OSError as e:
            logger.error("Could not read source for %r: %s", getattr(self, "name", "?"), e)
            text = ""
        self._source_cache = text
        return text

    # ── effect-context wiring ────────────────────────────────────────────

    def build_effect_context(self, context):
        """Translate a live ``SecondBrainContext`` into an ``EffectContext``.

        This is the narrowing: everything the plugin is *not* given (db handles,
        service objects, the runtime) stays on this side of the line."""
        from effects.interpreter import EffectContext

        services = getattr(context, "services", None) or {}
        ectx = EffectContext(
            db=getattr(context, "db", None),
            llm=self._llm_for(context, services),
            embedder=services.get("text_embedder"),
            read_roots=self._read_roots(context),
            write_roots=self._write_roots(context),
            free_write_roots=self._free_write_roots(context),
            paths=self._paths(context),
            context_provider=self._context_provider(context),
            ask_user=self._ask_user(context),
            gate_model_calls_after_read=bool(
                self._config(context).get("gate_model_calls_after_read")),
            tool_name=getattr(self, "name", "plugin"),
            session_key=getattr(context, "session_key", None),
            conversation_id=self._conversation_id(context),
            user_id=getattr(context, "user_id", None),
        )
        # The gate closes over the context it guards, so it can see what the run
        # has already read. Attached after construction for that reason.
        ectx.egress_gate = self._egress_gate(context, ectx)
        return ectx

    def _llm_for(self, context, services: dict):
        """The model a ``Complete`` should reach: the session's, not the global.

        A session can select a profile, so ``services["llm"]`` (the router's
        global default) is the wrong answer whenever one has. Resolving here
        means a plugin's model call uses the same brain as the conversation it
        is running inside — which is what makes a sandboxed compactor equivalent
        to the in-process one it replaces. Falls back to the router if profile
        resolution is unavailable."""
        runtime = getattr(context, "runtime", None)
        if runtime is None:
            return services.get("llm")
        try:
            from runtime.runtime_config import active_llm
            return active_llm(runtime, self._session(context)) or services.get("llm")
        except Exception:  # noqa: BLE001 — profile resolution is best-effort
            return services.get("llm")

    def _config(self, context) -> dict:
        """The live config dict, or an empty one."""
        return getattr(context, "config", None) or {}

    def _read_roots(self, context):
        """Roots the plugin may read under. Project root first, so a relative
        path resolves against it."""
        from paths import DATA_DIR
        roots = self._config(context).get("sandbox_read_roots")
        if roots:
            return [Path(r) for r in roots]
        base = []
        if getattr(context, "root_dir", None):
            base.append(Path(context.root_dir))
        base.append(DATA_DIR)
        return base

    def _write_roots(self, context):
        """Outer confinement: where a write is permitted at all. Whether a given
        write needs approval is a separate question — see ``_free_write_roots``."""
        from paths import DATA_DIR
        roots = self._config(context).get("sandbox_write_roots")
        if roots:
            return [Path(r) for r in roots]
        base = []
        if getattr(context, "root_dir", None):
            base.append(Path(context.root_dir))
        base.append(DATA_DIR)
        return base

    def _free_write_roots(self, context):
        """Write roots needing NO approval — frictionless drafting space.

        The plugin trees are deliberately absent: they are trees the kernel
        *interprets*, so an unapproved write into one is a sandbox escape. See
        the deferred-execution rule in effects/PRIMITIVES.md."""
        from paths import SCRATCH_DIR
        free = [SCRATCH_DIR]
        try:
            from plugins.helpers.memory_paths import memory_root
            free.append(memory_root(getattr(context, "user_id", None)))
        except Exception:  # noqa: BLE001 — memory package may be absent
            pass
        for extra in (self._config(context).get("sandbox_free_write_roots") or []):
            free.append(Path(extra))
        return free

    def _paths(self, context):
        """Non-secret resolved locations, readable via ReadContext("paths").
        Only *where things are* — never config values or keys."""
        from paths import DATA_DIR
        out = {"data": str(DATA_DIR), "scratch": str(DATA_DIR / "sandbox_scratch")}
        if getattr(context, "root_dir", None):
            out["root"] = str(Path(context.root_dir))
        try:
            from plugins.helpers.memory_paths import memory_root
            out["memory_root"] = str(memory_root(getattr(context, "user_id", None)))
        except Exception:  # noqa: BLE001 — memory package may be absent
            pass
        try:
            from plugins.helpers.plugin_paths import PLUGIN_ROOTS
            roots = [str(r.path / "skills") for r in PLUGIN_ROOTS
                     if (r.path / "skills").is_dir()]
            if roots:
                out["skills_roots"] = roots
        except Exception:  # noqa: BLE001 — skills package may be absent
            pass
        return out

    def _session(self, context):
        """The live RuntimeSession, if reachable."""
        runtime = getattr(context, "runtime", None)
        key = getattr(context, "session_key", None)
        if runtime is None or not key:
            return None
        return (getattr(runtime, "sessions", {}) or {}).get(key)

    def _conversation_id(self, context):
        """The current conversation id, via the live session if present."""
        session = self._session(context)
        return getattr(session, "conversation_id", None) if session else None

    def _context_provider(self, context):
        """Resolve the declared view against the conversation history."""
        session = self._session(context)

        def provider(view: str, k: int | None) -> str:
            if view == "params_only":
                return ""
            history = list(getattr(session, "history", []) or [])
            if view == "last_k":
                history = history[-(k or self.view_k):]
            return json.dumps(history, default=str)

        return provider

    def _ask_user(self, context):
        """Wire ``AskUser`` to the session's input prompt, if a human is there.

        Returns ``None`` — meaning the request fails fast — when there is no
        input channel or the session is unattended. Attendance is a liveness
        question, not a permission one: a scheduled subagent has nobody to
        answer, and blocking its turn on a prompt no one will see is a hang, not
        a safeguard. ``runtime.is_attended`` is the kernel's single reader for
        this, so background drivers inherit the behaviour automatically."""
        request_input = getattr(context, "request_user_input", None)
        if request_input is None:
            return None
        runtime = getattr(context, "runtime", None)
        session_key = getattr(context, "session_key", None)
        if runtime is not None and session_key:
            try:
                if not runtime.is_attended(session_key):
                    return None
            except Exception:  # noqa: BLE001 — an unreadable runtime is not attended
                return None

        def ask(title: str, prompt: str, choices: list[str]):
            reply = request_input(title, prompt, choices=choices) if choices \
                else request_input(title, prompt)
            # Frontends answer with either a bare string or a request object
            # carrying one; normalise so plugins only ever see text.
            if reply is None or isinstance(reply, str):
                return reply
            return getattr(reply, "response", None) or getattr(reply, "answer", None)

        return ask

    def _egress_gate(self, context, ectx):
        """Kernel-served model calls pass; boundary-crossing actions route
        through the approval surface with a legible target.

        The approval prompt names what the run has **already read**, because
        that is the question a human is actually being asked. "Allow this HTTP
        call" and "allow this HTTP call from a plugin that just read your SSH
        key" look identical to a per-request check and are not remotely the same
        decision. The taint list is what makes the second one visible.

        ``Complete``/``Embed`` still pass silently by default — the keys stay
        kernel-side and read-then-summarise is the common wanted case — unless
        ``gate_model_calls_after_read`` is set, in which case transmitting local
        data to a model endpoint needs an explicit approval too.
        """
        from effects.interpreter import describe_taint

        def gate(request):
            model_call = request.type in ("complete", "embed")
            if model_call and not (ectx.gate_model_calls_after_read and ectx.taint):
                return True, ""
            approve = getattr(context, "approve_command", None)
            if approve is None:
                return False, "no approval surface available for egress"
            note = describe_taint(ectx.taint)
            label = f"{getattr(self, 'name', 'plugin')!r} {request.type}"
            if note:
                label = f"{label} — {note}"
            ok = approve(egress_target(request), label)
            reason = getattr(context, "approval_denial_reason", "") or "egress denied by user"
            return ok, "" if ok else reason

        return gate

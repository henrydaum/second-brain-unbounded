"""
Tool interface.

Tools are the on-demand capability layer of Second Brain.
A tool accepts structured input, inspects local state or external systems,
and returns a ToolResult that is useful both to frontends and to the LLM.

Unlike tasks, tools do not run automatically over every file. They are
called explicitly by the agent, the UI, or other tools and return
immediately.

Tool schemas map directly into LLM function calling:
    - name        -> function name
    - description -> function description
    - parameters  -> JSON schema for arguments

The same tool contract is used everywhere: REPL, installed frontends, package
commands, and agent turns.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("Tool")


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


@dataclass(init=False)
class ToolResult:
    """
    The standardized result returned by every tool.

    success:
        Whether the tool call succeeded.
    error:
        Human-readable failure reason when success is False.
    data:
        Structured payload for frontends, tables, or debugging. This is not
        sent directly to the LLM.
    llm_summary:
        Concise model-facing summary of what happened. On success, this should
        carry the facts, changes, paths, counts, or constraints the model
        needs for its next step.
    attachment_paths:
        Local file paths for frontend rendering. These are not sent directly to
        the LLM, although image paths may later be passed back on a model call.
    """
    success: bool = True
    error: str = ""
    data: Any = None
    llm_summary: str = ""
    attachment_paths: list[str] = field(default_factory=list)

    def __init__(
        self,
        success: bool = True,
        error: str = "",
        data: Any = None,
        llm_summary: str = "",
        attachment_paths: list[str] | None = None,
    ):
        """Initialize the tool result."""
        self.success = success
        self.error = error
        self.data = data
        self.llm_summary = llm_summary
        self.attachment_paths = self._normalize_attachment_paths(attachment_paths)

    @staticmethod
    def _normalize_attachment_paths(*path_lists) -> list[str]:
        """Internal helper to normalize attachment paths."""
        normalized = []
        seen = set()
        for paths in path_lists:
            if not paths:
                continue
            for path in paths:
                if path in seen:
                    continue
                seen.add(path)
                normalized.append(path)
        return normalized

    def to_dict(self, base_url: str = "") -> dict:
        """Serialize for HTTP API responses.

        Args:
            base_url: If provided, each attachment gets a fetchable ``url``
                      pointing at the ``/files`` endpoint (e.g. ``http://host:port``).
        """
        from pathlib import Path
        from urllib.parse import quote
        from plugins.services.helpers.parser_registry import get_modality

        attachments = []
        for p in self.attachment_paths:
            modality = get_modality(Path(p).suffix)
            att = {"path": p, "modality": modality}
            if base_url:
                att["url"] = f"{base_url}/files?path={quote(p, safe='')}"
            attachments.append(att)

        return {
            "success": self.success,
            "error": self.error,
            "data": self.data,
            "llm_summary": self.llm_summary,
            "attachments": attachments,
        }

    @staticmethod
    def failed(error: str) -> "ToolResult":
        """Handle failed."""
        return ToolResult(success=False, error=error)


class BaseTool:
    """
    The contract every tool implements.

    Class attributes (override these):
        name:
            Stable identifier used everywhere the tool is referenced.
        description:
            Short operational description. This is also the LLM-visible tool
            description, so it should explain what the tool does, when to use
            it, and any important limits.
        parameters:
            JSON Schema describing the input arguments.
        requires_services:
            Service names that must be loaded before the tool can run.

    Methods (override these):
        run(...) -> see ``contract`` below.

    Execution contract
    ------------------
    ``contract`` selects what ``run`` means and how the kernel executes it:

    - ``"effects"`` (the target) — ``run(self, params)`` is a **generator**
      yielding typed requests from ``effects.vocabulary`` and returning a
      ``Respond``. The tool never touches a db, socket, or file directly. Such a
      tool runs either in-process or in a subprocess depending on *provenance*
      (see ``trusted``), with identical semantics either way.
    - ``"legacy"`` (the default, being migrated out) — ``run(self, context,
      **kwargs) -> ToolResult``, executed in-process with the live context.

    The kernel always enters through :meth:`perform`, never ``run`` directly, so
    the registry does not care which contract a tool implements.
    """

    # --- Execution contract ---
    contract: str = "legacy"

    # --- Identity ---
    name: str = ""
    description: str = ""
    parameters: dict = {}

    # --- Capability declaration (``contract = "effects"`` only) ---
    # The effect request types this tool may issue. Its danger tier is *derived*
    # from these (never author-asserted), and an undeclared request at runtime is
    # a hard reject.
    declared_requests: list[str] = []

    # How much conversation the tool may read: "full" | "last_k" | "params_only".
    # The narrower the view, the smaller the trust surface.
    view: str = "params_only"
    view_k: int = 6

    # --- Sandbox resource limits (untrusted mode only; enforced by the runner) ---
    # timeout_s meters the CHILD's own compute wall-clock (the clock stops while
    # a request sits kernel-side, e.g. on an approval dialog). memory_mb is
    # enforced by the parent's psutil watchdog everywhere, plus RLIMIT_AS on
    # Linux and a Job Object on Windows. cpu_seconds sets RLIMIT_CPU on POSIX.
    timeout_s: float = 30.0
    memory_mb: int = 512
    cpu_seconds: int = 30

    # --- Service requirements ---
    requires_services: list[str] = []
    dependencies_files: list[str] = []
    dependencies_pip: list[str] = []
    # Tool names this tool invokes via context.call_tool. Declared deps stay
    # callable (hidden) when this tool is whitelisted into an agent scope,
    # even when the call site isn't a literal string the regex fallback can see.
    dependencies_tools: list[str] = []

    # --- Agent controls ---
    max_calls: int = 3           # Max times the agent can call this tool per message
    background_safe: bool = True # When False, refuses to run from a non-active session

    # --- Discovery ---
    # When False, the plugin discoverer skips this tool. Use for tools that
    # need per-call construction args and are instantiated manually instead.
    auto_register: bool = True

    # --- Config settings this plugin needs ---
    # Each entry is a tuple:
    # (title, variable_name, description, default, type_info)
    # Same format as SETTINGS_DATA in config_data.py.
    config_settings: list = []

    def __init_subclass__(cls, **kwargs):
        """Copy mutable defaults, and validate the effects contract at definition
        time so a typo surfaces at import rather than as a silent capability gap."""
        super().__init_subclass__(**kwargs)
        for attr in ("parameters", "requires_services", "dependencies_files", "dependencies_pip",
                     "dependencies_tools", "config_settings", "declared_requests"):
            value = getattr(cls, attr)
            if isinstance(value, (dict, list)):
                setattr(cls, attr, value.copy())
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
                f"{cls.__name__}: declared_requests is only meaningful with "
                f'contract = "effects"')

    @property
    def danger_tier(self) -> str:
        """The tool's danger tier: the max tier across ``declared_requests``.

        Derived, never asserted — a tool cannot claim to be safer than the
        requests it declares."""
        from effects.declarations import derive_tier
        return derive_tier(self.declared_requests)

    # --- Agent system-prompt contribution ---
    # Static guidance injected into the agent's system prompt when this tool is
    # in scope. Override agent_prompt_for() instead for dynamic text.
    agent_prompt: str = ""

    def agent_prompt_for(self, ctx) -> str:
        """Guidance for the agent system prompt, or '' to contribute nothing.

        ``ctx`` is a PromptContext (db/services/orchestrator/config/scope/...).
        Default returns the static ``agent_prompt``; override for dynamic text."""
        return self.agent_prompt

    def run(self, context, **kwargs) -> ToolResult:
        """Execute the tool. Signature depends on ``contract`` — see the class
        docstring. The kernel calls :meth:`perform`, not this."""
        raise NotImplementedError(f"Tool '{self.name}' must implement run()")

    # ── kernel entry point ───────────────────────────────────────────────

    def perform(self, context, **kwargs) -> ToolResult:
        """Run the tool. The single entry point the registry uses.

        For a ``legacy`` tool this is just ``run(context, **kwargs)``. For an
        ``effects`` tool it builds an :class:`~effects.interpreter.EffectContext`
        from the live context and hands the body to whichever executor the tool's
        provenance selects — both of which drive the same generator through the
        same interpreter, so the mode changes only whether a process boundary
        exists."""
        if self.contract != "effects":
            return self.run(context, **kwargs)

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

        if self.trusted(context):
            from sandbox.local import run_local_tool
            outcome = run_local_tool(
                instance=self, params=kwargs,
                declared=self.declared_requests, effect_ctx=ectx)
        else:
            from sandbox.runner import run_sandbox_tool
            outcome = run_sandbox_tool(
                source=self._source_text(), params=kwargs,
                declared=self.declared_requests, effect_ctx=ectx,
                timeout=float(context.config.get("tool_timeout", self.timeout_s)),
                memory_mb=self.memory_mb, cpu_seconds=self.cpu_seconds)

        return ToolResult(
            success=outcome.success,
            error=outcome.error,
            data=outcome.data,
            llm_summary=outcome.summary,
            attachment_paths=outcome.attachment_paths,
        )

    def trusted(self, context) -> bool:
        """Whether this tool runs in-process. Provenance only — never a config
        flag, and never anything the tool asserts about itself.

        ``sandbox_trust_all`` forces trusted mode for every plugin. It exists for
        the migration's all-trusted equivalence check and for debugging, not as a
        deployment mode; it is deliberately global and blunt so it cannot quietly
        become per-plugin policy."""
        from plugins.helpers.plugin_paths import is_trusted

        if (context.config or {}).get("sandbox_trust_all"):
            return True
        return is_trusted(getattr(self, "_source_path", ""))

    def _source_text(self) -> str:
        """The tool's own source, read lazily and cached.

        Only the untrusted path needs it (the child is fed source, not an
        object), so a trusted tool never pays this read."""
        cached = getattr(self, "_source_cache", None)
        if cached is not None:
            return cached
        from pathlib import Path
        try:
            text = Path(getattr(self, "_source_path", "")).read_text(encoding="utf-8")
        except OSError as e:
            logger.error("Could not read source for tool %r: %s", self.name, e)
            text = ""
        self._source_cache = text
        return text

    # ── effect-context wiring (effects contract only) ────────────────────

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
        reject). Whether a given write needs approval is a separate question —
        see ``_free_write_roots``."""
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
        """The subset of write roots needing NO approval — frictionless drafting
        space. Scratch and the user's memory folder are free; more can be added
        via ``sandbox_free_write_roots``.

        The sandbox-plugin tree is deliberately **not** free: it is a tree the
        kernel *interprets*, so an unapproved write into it is a sandbox escape.
        See the deferred-execution rule in effects/PRIMITIVES.md."""
        from paths import SCRATCH_DIR
        free = [SCRATCH_DIR]
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

        Only *where things are* — never config values or keys."""
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

    def _session(self, context):
        """The live RuntimeSession, if reachable."""
        runtime = context.runtime
        if runtime is None or not context.session_key:
            return None
        return (getattr(runtime, "sessions", {}) or {}).get(context.session_key)

    def _conversation_id(self, context):
        """The current conversation id, via the live session if present."""
        session = self._session(context)
        return getattr(session, "conversation_id", None) if session else None

    def _context_provider(self, context):
        """Resolve the tool's declared view against the conversation history."""
        session = self._session(context)

        def provider(view: str, k: int | None) -> str:
            if view == "params_only":
                return ""
            history = list(getattr(session, "history", []) or [])
            if view == "last_k":
                history = history[-(k or self.view_k):]
            return json.dumps(history, default=str)

        return provider

    def _egress_gate(self, context):
        """Kernel-served model calls (complete, embed) pass; boundary-crossing
        actions route through the approval surface with a legible target."""
        def gate(request):
            if request.type in ("complete", "embed"):
                return True, ""
            approve = context.approve_command
            if approve is None:
                return False, "no approval surface available for egress"
            ok = approve(_egress_target(request), f"tool '{self.name}' {request.type}")
            return ok, "" if ok else (context.approval_denial_reason or "egress denied by user")

        return gate

    def to_schema(self) -> dict:
        """Export the tool as an OpenAI-compatible function schema."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            }
        }

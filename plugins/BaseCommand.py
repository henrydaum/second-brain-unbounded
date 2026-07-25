"""Slash-command plugin contract."""

from __future__ import annotations

import logging

from plugins.EffectsContract import EffectsContract
from state_machine.conversation import FormStep

logger = logging.getLogger("Command")


class BaseCommand(EffectsContract):
    """Base command.

    Execution contract
    ------------------
    ``contract`` selects what ``run`` and ``form`` mean:

    - ``"legacy"`` (default, being migrated out) — ``run(args, context) -> str``
      and ``form(args, context) -> list[FormStep]``, in-process with the live
      context.
    - ``"effects"`` — both are **generators** over ``params`` alone. ``run``
      returns a markdown string (or a ``Respond`` carrying one); ``form`` returns
      a list of plain dicts, which the kernel converts into ``FormStep``.

    ``form`` is a generator too, not a static declaration, because nearly every
    real form is dynamic — it lists conversations, services, or profiles to build
    its choices. Those are ordinary read requests, so they travel the same
    boundary as anything else rather than getting a privileged side channel.

    The kernel enters through :meth:`perform` and :meth:`form_steps`, never
    ``run``/``form`` directly, so the registry does not care which contract a
    command implements.
    """

    name: str = ""
    description: str = ""
    category: str = "Other"
    hide_from_help: bool = False
    require_approval: bool = False
    approval_actor_id: str | None = None
    config_settings: list = []
    dependencies_files: list[str] = []
    dependencies_pip: list[str] = []

    # --- Agent system-prompt contribution ---
    # Static guidance injected into the agent's system prompt when this command
    # is in scope. Override agent_prompt_for() instead for dynamic text.
    agent_prompt: str = ""

    def __init_subclass__(cls, **kwargs):
        """Internal helper to prevent subclasses sharing mutable metadata."""
        super().__init_subclass__(**kwargs)
        for attr in ("config_settings", "dependencies_files", "dependencies_pip",
                     "declared_requests"):
            value = getattr(cls, attr)
            if isinstance(value, list):
                setattr(cls, attr, value.copy())
        cls.validate_effects_declaration()

    def agent_prompt_for(self, ctx) -> str:
        """Guidance for the agent system prompt, or '' to contribute nothing.

        ``ctx`` is a PromptContext (db/services/orchestrator/config/scope/...).
        Default returns the static ``agent_prompt``; override for dynamic text."""
        return self.agent_prompt

    def form(self, args: dict, context) -> list[FormStep]:
        """Handle form."""
        return []

    def arg_completions(self, context) -> list[str]:
        """Handle arg completions."""
        return []

    def run(self, args: dict, context) -> str | None:
        """Execute `/BaseCommand` for the active session."""
        raise NotImplementedError(f"Command '{self.name}' must implement run()")

    # ── kernel entry points ──────────────────────────────────────────────

    def perform(self, args: dict, context) -> str | None:
        """Run the command. The single entry point the registry dispatches to."""
        if self.contract != "effects":
            return self.run(dict(args or {}), context)
        outcome = self._perform_effects(context, dict(args or {}))
        if not outcome.success:
            return f"Command '/{self.name}' failed: {outcome.error}"
        # A command's result *is* its user-facing markdown, so ``summary`` is the
        # canonical field. ``data`` is accepted when it carries a string because
        # ``Respond(data=...)`` is the natural thing to write when the whole
        # return value is the text -- and silently returning None for it would be
        # a maddening bug to chase.
        if outcome.summary:
            return outcome.summary
        return outcome.data if isinstance(outcome.data, str) and outcome.data else None

    def form_steps(self, args: dict, context) -> list[FormStep]:
        """The command's form, as live ``FormStep``s.

        A legacy command builds them directly. An effects command returns plain
        dicts from a generator and the kernel constructs the steps here — the
        command never holds a ``FormStep``, which keeps the form declarative and
        keeps validators kernel-side.

        Never raises: a form that fails is an empty form, because the callers
        (help text, argument parsing, the state machine's form factory) all treat
        "no form" as a valid answer and must not break on one bad command."""
        try:
            if self.contract != "effects":
                return self.form(dict(args or {}), context)
            outcome = self._perform_effects(context, dict(args or {}), method="form")
            if not outcome.success:
                logger.warning("Command '/%s' form failed: %s", self.name, outcome.error)
                return []
            return _to_form_steps(outcome.data)
        except Exception:  # noqa: BLE001 — a broken form must not break the caller
            logger.exception("Command '/%s' form raised", self.name)
            return []


_FORM_STEP_FIELDS = {
    "name", "prompt", "required", "type", "enum", "enum_labels",
    "default", "prompt_when_missing", "columns",
}


def _to_form_steps(spec) -> list[FormStep]:
    """Build ``FormStep``s from a plugin-supplied list of dicts.

    Unknown keys are dropped rather than raising: the spec crosses a process
    boundary from code the kernel does not trust, so it is validated, not
    believed. ``validator`` is deliberately not accepted — it is a callable, and
    a sandboxed command cannot hand the kernel one to execute."""
    steps = []
    for entry in spec or []:
        if isinstance(entry, FormStep):
            steps.append(entry)
            continue
        if not isinstance(entry, dict) or not entry.get("name"):
            continue
        kwargs = {k: v for k, v in entry.items() if k in _FORM_STEP_FIELDS}
        try:
            steps.append(FormStep(**kwargs))
        except (TypeError, ValueError):
            logger.warning("Skipping malformed form step: %r", entry)
    return steps

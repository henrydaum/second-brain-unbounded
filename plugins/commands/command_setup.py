"""Slash command plugin for `/setup` — onboarding ramp.

Three phases, all in one pass:
  1. Packages — a fresh kernel ships no LLM backend or frontend, so setup leads
     by installing the `starter` bundle (or `full`), and points at /packages for
     more. Skipped automatically once an LLM backend is already installed.
  2. LLM — configure a default profile (Atlas Cloud fast-path or another provider,
     via the LiteLLM backend).
  3. Telegram — configure the bot, but only when the Telegram frontend is (being)
     installed.
"""

from plugins.BaseCommand import BaseCommand


ATLAS_BASE_URL = "https://api.atlascloud.ai/v1"
ATLAS_CODING_PLAN_URL = "https://www.atlascloud.ai/console/coding-plan"
ATLAS_DEFAULT_MODEL = "minimaxai/minimax-m2.7"
DEFAULT_ENV_VAR = "ATLAS_API_KEY"
DEFAULT_CONTEXT_SIZE = 0
DEFAULT_BACKEND = "LiteLLMService"

STARTER_BUNDLE = "bundle_starter"
FULL_BUNDLE = "bundle_full"
TELEGRAM_PACKAGE = "frontend_telegram"

WELCOME_PROMPT = (
    "Welcome to Second Brain.\n\n"
    "The kernel ships almost nothing on its own — capabilities are installed from a "
    "package store. The `starter` bundle is the recommended first install: an LLM "
    "backend (LiteLLM, which reaches most providers), the Telegram frontend, file "
    "read/edit, sql & shell tools, ask-user-question, plugin authoring, and memory + "
    "auto-title tasks. `full` adds every file parser, transcription/OCR, and the "
    "indexing & search pipeline (a larger download).\n\n"
    "You can browse and install more anytime with /packages.\n\n"
    "Second Brain is sponsored by Atlas Cloud — a fast way to get an API key: "
    f"{ATLAS_CODING_PLAN_URL}"
)

LLM_INTRO_PROMPT = (
    "Let's set your default LLM profile. Atlas Cloud is the sponsored fast-path "
    "(300+ models behind one key); or point Second Brain at any other provider."
)

KEY_SOURCE_PROMPT = (
    "To use Atlas Cloud you need an API key. Sign up at "
    f"{ATLAS_CODING_PLAN_URL} and create an API key, then choose how you want to supply it:"
)

ENV_VAR_PROMPT = (
    "Enter the name of the environment variable that holds your Atlas key. "
    "You'll need to set this variable in your shell/system before Second Brain can call Atlas (for example on Windows: `setx ATLAS_API_KEY your-key`)."
)

OTHER_MODEL_PROMPT = (
    "Enter the LiteLLM model name, including the provider prefix when needed. "
    "Examples: `openai/gpt-4o-mini`, `anthropic/claude-3-5-sonnet-latest`, "
    "`minimax/MiniMax-M2.7`. For an OpenAI-compatible endpoint (set the base URL "
    "below), a plain id like `deepseek-ai/deepseek-v4-pro` is auto-routed through "
    "the openai provider."
)
OTHER_SERVICE_PROMPT = (
    "How should Second Brain connect to this model?\n\n"
    "Installed LLM backends are normal service plugins."
)
OTHER_ENDPOINT_PROMPT = (
    "Optional provider base URL or LiteLLM proxy URL. Leave blank for the provider default. "
    "For local models or self-hosted gateways, paste the full base URL."
)
OTHER_KEY_PROMPT = (
    "API key. You can paste the key directly, enter the name of an environment variable that holds it, or leave it blank to let the backend read its own environment."
)
OTHER_CONTEXT_PROMPT = (
    "Context window size in tokens. Use 0 if you don't know — Second Brain will still work, it just won't proactively compact."
)

TELEGRAM_PROMPT = (
    "Now let's set up Telegram. The Telegram frontend gives you a much better experience than the REPL — "
    "push notifications, attachments, inline buttons, and access from your phone.\n\n"
    "You'll need:\n"
    "  1. A bot token from @BotFather on Telegram (https://t.me/BotFather → /newbot)\n"
    "  2. Your Telegram user ID — message @userinfobot and it will reply with your numeric ID"
)
TELEGRAM_TOKEN_PROMPT = "Paste the bot token from @BotFather."
TELEGRAM_USER_PROMPT = (
    "Enter your Telegram user ID (a number from @userinfobot). Only this user will be allowed to talk to the bot."
)

PACKAGES_SECTION = (
    "Get more with /packages:\n"
    "  /packages available        — browse the store by category\n"
    "  /packages install <id>     — install a package or bundle\n"
    "  Handy bundles: bundle_all_parsers, bundle_indexing_search, "
    "bundle_web_search, bundle_gmail, bundle_mcp, bundle_google_drive, "
    "bundle_scheduling, bundle_plan_mode, bundle_full."
)


class SetupCommand(BaseCommand):
    """Slash-command handler for `/setup`.

    The command a fresh install depends on, and the one most exposed to the scope
    question: it writes an API key, installs code from the network, and saves
    Telegram credentials into a plugin's config file *before that plugin exists*.
    That last case is why ``WriteConfig`` carries an explicit ``plugin`` scope —
    discovery cannot classify a key whose owner is not installed yet, so the
    caller has to say which file it means.

    Connectivity checking moved kernel-side with the conversion. Opening a socket
    to probe the network is exactly the ambient reach a sandboxed body must not
    have, and the caller only ever wanted a legible failure instead of an opaque
    download error.
    """
    name = "setup"
    description = "Onboarding: install a starter bundle, then configure an LLM and Telegram"
    category = "System"

    contract = "effects"
    declared_requests = ["read_context", "read_config", "write_config", "package_op"]

    def form(self, params):
        """Build the dynamic onboarding form."""
        backends = yield from _view("llm_backends")
        steps = []

        # Phase 1 — packages. Only lead with this when there is no LLM backend
        # yet (a fresh install). A returning user skips straight to reconfiguring.
        if not backends:
            steps.append({
                "name": "install_choice", "required": True, "columns": 1,
                "prompt": WELCOME_PROMPT,
                "enum": [STARTER_BUNDLE, FULL_BUNDLE, "skip"],
                "enum_labels": [
                    "Install the starter bundle (recommended)",
                    "Install the full bundle (everything — larger download)",
                    "Skip — I'll use /packages myself",
                ]})
            choice = params.get("install_choice")
            if not choice or choice == "skip":
                return steps
            # starter and full both include the LiteLLM backend + Telegram frontend.
            will_have_telegram = True
        else:
            will_have_telegram = yield from _telegram_installed()

        # Phase 2 — LLM profile.
        steps.append({"name": "llm_choice", "required": True, "columns": 1,
                      "prompt": LLM_INTRO_PROMPT, "enum": ["atlas", "other"],
                      "enum_labels": ["Set up Atlas Cloud", "Use another provider"]})
        llm_choice = params.get("llm_choice")
        if llm_choice == "atlas":
            steps += _atlas_steps(params)
        elif llm_choice == "other":
            steps += _other_steps(backends or [DEFAULT_BACKEND])

        # Phase 3 — Telegram, once the LLM branch is satisfied and the frontend
        # is (being) installed.
        if will_have_telegram and _llm_steps_complete(params, llm_choice):
            steps += _telegram_steps(params)
        return steps

    def run(self, params):
        """Execute `/setup` for the active session."""
        from effects.vocabulary import PackageOp, Respond

        install_choice = params.get("install_choice")
        if install_choice == "skip":
            return Respond(data=_skip_section())

        sections = []
        warning = None

        # Phase 1 — install the chosen bundle before configuring anything that
        # depends on it. Bail clearly rather than pretend a half-set-up instance
        # is ready.
        if install_choice in (STARTER_BUNDLE, FULL_BUNDLE):
            result = yield PackageOp(name=install_choice, action="install")
            if not result.ok:
                return Respond(data=(
                    f"Couldn't install the `{install_choice}` bundle: {result.error}\n\n"
                    f"Resolve the issue (or try `/packages install {install_choice}`), "
                    "then re-run /setup."))
            sections.append(f"Installed the `{install_choice}` bundle.\n"
                            + _indent((result.value or {}).get("text") or ""))

        # Phase 2 — LLM profile.
        llm_choice = params.get("llm_choice")
        if llm_choice == "atlas":
            outcome = yield from _save_atlas(params)
            if isinstance(outcome, str):
                return Respond(data=outcome)
            section, warning = outcome
            sections.append(section)
        elif llm_choice == "other":
            outcome = yield from _save_other(params)
            if not outcome.startswith("LLM:"):
                return Respond(data=outcome)
            sections.append(outcome)

        # Phase 3 — Telegram.
        if params.get("telegram_choice") == "setup":
            sections.append((yield from _save_telegram(params)))
        elif params.get("telegram_choice") == "skip":
            sections.append("Telegram: skipped. Use /config to add `telegram_bot_token` "
                            "and `telegram_allowed_user_id` later.")

        sections.append(PACKAGES_SECTION)
        sections.append((yield from _location_section()))
        sections.append(_hint_section())
        if warning:
            sections.insert(0, warning)
        return Respond(data="\n\n".join(s for s in sections if s))


# ──────────────────────────────────────────────────────────────────────
# Step builders
# ──────────────────────────────────────────────────────────────────────

def _atlas_steps(params: dict) -> list[dict]:
    """Atlas Cloud key/model collection."""
    steps = [{"name": "key_source", "required": True, "columns": 1,
              "prompt": KEY_SOURCE_PROMPT, "enum": ["direct", "env_var"],
              "enum_labels": ["Paste the key directly",
                              "Use an environment variable (you'll set it yourself)"]}]
    if params.get("key_source") == "direct":
        steps.append({"name": "api_key", "required": True,
                      "prompt": "Paste your Atlas Cloud API key."})
    elif params.get("key_source") == "env_var":
        steps.append({"name": "env_var_name", "required": True,
                      "default": DEFAULT_ENV_VAR, "prompt": ENV_VAR_PROMPT})
    if params.get("key_source"):
        steps.append({"name": "model_name", "required": False,
                      "default": ATLAS_DEFAULT_MODEL, "prompt_when_missing": True,
                      "prompt": ("Model name to use as your default profile. You can "
                                 "change this later with /llm.")})
    return steps


def _other_steps(backends: list[str]) -> list[dict]:
    """Generic LLM profile collection (mirrors /llm add)."""
    return [
        {"name": "other_model_name", "required": True, "prompt": OTHER_MODEL_PROMPT},
        {"name": "other_service_class", "required": True, "columns": 1,
         "enum": backends, "default": backends[0], "prompt": OTHER_SERVICE_PROMPT},
        {"name": "other_endpoint", "required": False, "default": "",
         "prompt_when_missing": True, "prompt": OTHER_ENDPOINT_PROMPT},
        {"name": "other_api_key", "required": False, "default": "",
         "prompt_when_missing": True, "prompt": OTHER_KEY_PROMPT},
        {"name": "other_context_size", "required": False, "type": "integer",
         "default": 0, "prompt_when_missing": True, "prompt": OTHER_CONTEXT_PROMPT},
    ]


def _telegram_steps(params: dict) -> list[dict]:
    """Telegram bot credential collection."""
    steps = [{"name": "telegram_choice", "required": True, "columns": 1,
              "prompt": TELEGRAM_PROMPT, "enum": ["setup", "skip"],
              "enum_labels": ["Set up Telegram", "Skip — I'll use the REPL for now"]}]
    if params.get("telegram_choice") == "setup":
        steps.append({"name": "telegram_bot_token", "required": True,
                      "prompt": TELEGRAM_TOKEN_PROMPT})
        steps.append({"name": "telegram_allowed_user_id", "required": True,
                      "type": "integer", "prompt": TELEGRAM_USER_PROMPT})
    return steps


def _llm_steps_complete(params: dict, choice) -> bool:
    """Whether the LLM branch has collected enough to move on to Telegram."""
    if choice == "atlas":
        source = params.get("key_source")
        if source == "direct":
            return bool(params.get("api_key"))
        if source == "env_var":
            return bool(params.get("env_var_name"))
        return False
    if choice == "other":
        return bool(params.get("other_model_name") and params.get("other_service_class"))
    return False


# ──────────────────────────────────────────────────────────────────────
# Persistence
# ──────────────────────────────────────────────────────────────────────

def _save_atlas(params: dict):
    """Persist an Atlas Cloud LLM profile. Returns (section, warning) or an error."""
    source = params.get("key_source")
    if source == "direct":
        key_field = (params.get("api_key") or "").strip()
    elif source == "env_var":
        key_field = (params.get("env_var_name") or DEFAULT_ENV_VAR).strip() or DEFAULT_ENV_VAR
    else:
        return "Setup cancelled."
    if not key_field:
        return "An API key (or environment variable name) is required."

    model = (params.get("model_name") or ATLAS_DEFAULT_MODEL).strip() or ATLAS_DEFAULT_MODEL
    error = yield from _install_profile(model, {
        "llm_endpoint": ATLAS_BASE_URL,
        "llm_api_key": key_field,
        "llm_context_size": DEFAULT_CONTEXT_SIZE,
        "llm_service_class": DEFAULT_BACKEND,
    })
    if error:
        return error

    section = (f"LLM: Atlas Cloud set up. Default profile: {model}\n"
               f"  Endpoint: {ATLAS_BASE_URL}\n"
               f"  Coding plan: {ATLAS_CODING_PLAN_URL}\n"
               "  Use /llm to edit the profile or add more models.")
    warning = None
    if source == "env_var":
        # The plugin cannot read the environment — that is ambient reach it does
        # not have — so this note is unconditional rather than conditional on the
        # variable actually being unset. A reminder the user does not need is
        # cheaper than a silent failure on their first message.
        warning = (f"Note: make sure ${key_field} is set in your environment before "
                   "sending your first message, or Atlas calls will fail.")
    return section, warning


def _save_other(params: dict):
    """Persist a generic LLM profile. Returns a section or an error string."""
    name = (params.get("other_model_name") or "").strip()
    if not name:
        return "Model name is required."
    try:
        size = int(params.get("other_context_size") or 0)
    except (TypeError, ValueError):
        size = 0
    service_class = ((params.get("other_service_class") or DEFAULT_BACKEND).strip()
                     or DEFAULT_BACKEND)
    endpoint = (params.get("other_endpoint") or "").strip()

    error = yield from _install_profile(name, {
        "llm_endpoint": endpoint,
        "llm_api_key": (params.get("other_api_key") or "").strip(),
        "llm_context_size": size,
        "llm_service_class": service_class,
    })
    if error:
        return error
    return (f"LLM: profile `{name}` added and set as default.\n"
            f"  Service class: {service_class}\n"
            f"  Endpoint: {endpoint or '(provider default)'}\n"
            "  Use /llm to edit or add more models.")


def _install_profile(name: str, profile: dict):
    """Add a profile and make it the default. Returns '' or an error message.

    Writing ``llm_profiles`` is also what hot-loads the backend: the kernel
    resyncs the router when that key changes, so there is nothing for the plugin
    to register."""
    from effects.vocabulary import ReadConfig, WriteConfig

    current = yield ReadConfig(key="llm_profiles")
    profiles = dict(current.value or {})
    profiles[name] = profile

    # scope="plugin" explicitly rather than relying on discovery to classify
    # these as plugin-declared. /setup is the *fresh install* path, so it must
    # not depend on service_llm's settings having been discovered yet -- that is
    # precisely the ordering that is least likely to hold here.
    written = yield WriteConfig(key="llm_profiles", value=profiles, scope="plugin")
    if not written.ok:
        return f"Could not save the LLM profile: {written.error}"
    written = yield WriteConfig(key="default_llm_profile", value=name, scope="plugin")
    if not written.ok:
        return f"Could not set the default LLM: {written.error}"
    return ""


def _save_telegram(params: dict):
    """Persist Telegram credentials into plugin config."""
    from effects.vocabulary import WriteConfig

    token = (params.get("telegram_bot_token") or "").strip()
    try:
        user_id = int(params.get("telegram_allowed_user_id") or 0)
    except (TypeError, ValueError):
        user_id = 0

    # scope="plugin" explicitly: the Telegram frontend may not be installed yet,
    # so discovery cannot tell these keys are plugin-owned.
    for key, value in (("telegram_bot_token", token),
                       ("telegram_allowed_user_id", user_id)):
        written = yield WriteConfig(key=key, value=value, scope="plugin")
        if not written.ok:
            return f"Telegram: could not save credentials ({written.error})."
    return (f"Telegram: configured for user {user_id}.\n"
            "  Restart Second Brain to bring the bot online, then send /start to "
            "your bot in Telegram.")


# ──────────────────────────────────────────────────────────────────────
# Sections
# ──────────────────────────────────────────────────────────────────────

def _view(name: str):
    """Yield one inventory view."""
    from effects.vocabulary import ReadContext

    result = yield ReadContext(view=name)
    return result.value or []


def _telegram_installed():
    """Whether the Telegram frontend has an install receipt."""
    catalog = yield from _view("packages")
    installed = catalog.get("installed", []) if isinstance(catalog, dict) else []
    return any(item.get("id") == TELEGRAM_PACKAGE for item in installed)


def _skip_section() -> str:
    """Guidance when the user declines the starter install."""
    return ("Skipped package install.\n\n"
            "Second Brain needs at least an LLM backend before it can do anything. "
            "When you're ready:\n"
            f"  /packages install {STARTER_BUNDLE}   — the recommended baseline\n"
            f"  /packages install {FULL_BUNDLE}      — everything\n"
            "  /packages available        — browse the store by category\n\n"
            "Then run /setup again to configure your LLM and Telegram.")


def _location_section():
    """One-paragraph summary of where things live on disk."""
    paths = yield from _view("paths")
    data_dir = paths.get("data", "(unknown)") if isinstance(paths, dict) else "(unknown)"
    return ("Files & data:\n"
            f"  DATA_DIR: {data_dir}\n"
            "  Holds your config (config.json, plugin_config.json), the SQLite "
            "database, the attachment cache, installed packages, and any sandbox "
            "plugins the agent writes for itself.\n"
            "  Run /locations to see existing plugins, and /config to view and edit "
            "your config files.")


def _hint_section() -> str:
    """Closing hint about how to continue."""
    return ("You're ready. Run /new to start a conversation, then just ask the LLM "
            "anything — how Second Brain works, what tools are available, how to set "
            "up a task, and more!")


def _indent(text: str) -> str:
    """Indent a block two spaces for nesting under a section header."""
    return "\n".join(f"  {line}" if line else line for line in (text or "").splitlines())

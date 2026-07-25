"""Support code for plugin paths."""

from dataclasses import dataclass
from pathlib import Path

from paths import DATA_DIR, INSTALLED_PLUGINS, ROOT_DIR, SANDBOX_PLUGINS


@dataclass(frozen=True)
class PluginRoot:
    """A physical tree that can contain mirrored plugin family folders."""
    name: str
    path: Path
    module: str
    built_in: bool = False


@dataclass(frozen=True)
class PluginDir:
    """A concrete plugin family directory under one root."""
    root: PluginRoot
    plugin_type: str
    family: str
    prefix: str

    @property
    def path(self) -> Path:
        return self.root.path / self.family

    def module_name(self, stem: str) -> str:
        return f"{self.root.module}.{self.family}.{stem}"


@dataclass(frozen=True)
class PluginPathInfo:
    """Plugin path info."""
    plugin_type: str
    path: Path
    built_in: bool
    module_name: str
    root_name: str


PLUGIN_ROOTS = (
    PluginRoot("built_in", ROOT_DIR / "plugins", "plugins", True),
    PluginRoot("sandbox", SANDBOX_PLUGINS, "sandbox_plugins"),
    PluginRoot("installed", INSTALLED_PLUGINS, "installed_plugins"),
)

PLUGIN_FAMILIES = {
    "tool": ("tools", "tool_"),
    "task": ("tasks", "task_"),
    "service": ("services", "service_"),
    "command": ("commands", "command_"),
    "frontend": ("frontends", "frontend_"),
}

PLUGIN_CONFIG = {
    plugin_type: tuple(PluginDir(root, plugin_type, family, prefix) for root in PLUGIN_ROOTS)
    for plugin_type, (family, prefix) in PLUGIN_FAMILIES.items()
}
ALLOWED_ROOTS = tuple(p.resolve() for p in (ROOT_DIR, DATA_DIR))

_BUILTIN_ROOT = next((r.path.resolve() for r in PLUGIN_ROOTS if r.built_in), None)


def is_builtin_path(path) -> bool:
    """Whether a plugin source path lives under the built-in (kernel) tree.

    Used by the supervisor to decide quarantine eligibility: only sandbox /
    installed plugins are quarantinable. An empty or unresolvable path is
    treated as built-in (conservative — never auto-disable something we can't
    locate)."""
    if not path:
        return True
    try:
        resolved = Path(path).resolve()
    except Exception:
        return True
    if _BUILTIN_ROOT is None:
        return True
    return resolved == _BUILTIN_ROOT or _BUILTIN_ROOT in resolved.parents


def trusted_hashes() -> set[str]:
    """SHA-256 hexdigests the user has reviewed and marked trusted.

    Trust binds to *reviewed bytes*, never to an origin: "it came from the
    store" is not evidence, because a store is just a place code arrives from.
    Editing a file changes its hash and silently drops it back to untrusted,
    which is the property that makes review meaningful.

    Read fresh each call from ``DATA_DIR/trusted_plugins.txt`` (one hexdigest per
    line, ``#`` comments allowed) so revoking trust takes effect without a
    restart. A missing file means "nothing extra is trusted" — fail closed.
    """
    registry = DATA_DIR / "trusted_plugins.txt"
    try:
        lines = registry.read_text(encoding="utf-8").splitlines()
    except OSError:
        return set()
    out = set()
    for line in lines:
        entry = line.split("#", 1)[0].strip().lower()
        if len(entry) == 64 and all(c in "0123456789abcdef" for c in entry):
            out.add(entry)
    return out


def file_digest(path) -> str | None:
    """SHA-256 of a plugin source file, or ``None`` if unreadable."""
    import hashlib

    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except (OSError, TypeError):
        return None


def is_trusted(path, *, trusted: set[str] | None = None) -> bool:
    """Whether a plugin at ``path`` may run in-process (trusted mode).

    Provenance decides, never self-assertion:

    1. Built-in kernel plugins are trusted — they ship with the kernel and are
       already inside the trusted computing base.
    2. Anything else is trusted only if its content hash is registered as
       reviewed (see :func:`trusted_hashes`).

    Everything else — sandbox-authored plugins, store installs, and any file
    that changed since review — runs sandboxed. An unreadable path is untrusted:
    the conservative direction here is the *opposite* of ``is_builtin_path``,
    because that gate protects against auto-disabling and this one protects
    against granting authority.
    """
    if is_builtin_path(path) and path:
        return True
    digest = file_digest(path)
    if digest is None:
        return False
    return digest in (trusted_hashes() if trusted is None else trusted)


def resolve_plugin_path(raw: str) -> tuple[Path | None, str | None]:
    """Resolve plugin path."""
    if not raw:
        return None, "plugin_path is required."
    p = Path(raw)
    if p.is_absolute():
        resolved = p.resolve()
    else:
        first = p.parts[0] if p.parts else ""
        if first in {"sandbox_plugins", "installed_plugins"}:
            resolved = (DATA_DIR / p).resolve()
        elif first == "plugins":
            resolved = (ROOT_DIR / p).resolve()
        else:
            root_path = (ROOT_DIR / p).resolve()
            data_path = (DATA_DIR / p).resolve()
            resolved = root_path if root_path.exists() or not data_path.exists() else data_path
    if not any(resolved == root or root in resolved.parents for root in ALLOWED_ROOTS):
        return None, f"Path is outside allowed roots: {resolved}"
    return resolved, None


def plugin_info(path: Path) -> tuple[PluginPathInfo | None, str | None]:
    """Handle plugin info."""
    path = path.resolve()
    name = path.name
    if path.suffix != ".py":
        return None, f"File name must end with .py, got '{name}'."
    for plugin_type, dirs in PLUGIN_CONFIG.items():
        for plugin_dir in dirs:
            if path.parent != plugin_dir.path.resolve():
                continue
            if not name.startswith(plugin_dir.prefix):
                return None, f"{plugin_type.title()} files must start with '{plugin_dir.prefix}', got '{name}'."
            return PluginPathInfo(plugin_type, path, plugin_dir.root.built_in, plugin_dir.module_name(path.stem), plugin_dir.root.name), None
    inferred = _infer_type(name)
    if inferred:
        locations = ", ".join(str(d.path.resolve()) for d in PLUGIN_CONFIG[inferred])
        return None, f"{inferred.title()} plugin '{name}' must live in one of: {locations}. Got {path.parent}."
    return None, f"Plugin file '{name}' is not in a known plugin folder."


def iter_plugin_dirs():
    """Yield concrete plugin family directories."""
    for plugin_type, dirs in PLUGIN_CONFIG.items():
        for plugin_dir in dirs:
            yield plugin_type, plugin_dir.path


def plugin_dirs(plugin_type: str) -> tuple[PluginDir, ...]:
    """Return plugin directories for one family in precedence order."""
    return PLUGIN_CONFIG[plugin_type]


def _infer_type(file_name: str) -> str | None:
    """Internal helper to handle infer type."""
    for plugin_type, (_family, prefix) in PLUGIN_FAMILIES.items():
        if file_name.startswith(prefix):
            return plugin_type
    return None

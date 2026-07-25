"""What a plugin actually consists of, and what it actually reaches for.

A plugin is rarely one file. It imports helpers, those helpers import other
helpers, and the import that matters — the one outside the standard library —
might be three files away from the thing you are looking at.

This module answers both halves of that with one walk:

- **The closure**: the plugin file plus every local file reachable from it by
  following relative imports. This is the unit that gets validated, shipped to
  the sandbox child, and hashed for trust. Not the file — the closure.
- **The outside reach**: every import in that closure the sandbox gate will not
  admit, and which file asked for it. This is what a trust prompt is made of.

**Read from the code, never from the declarations.** ``dependencies_files`` and
``dependencies_pip`` answer "what should the package manager install"; being
wrong there means the plugin breaks, which is safe. This answers "what could
this reach", where being wrong means someone gets owned. A plugin that declares
nothing and imports ``requests`` on line 40 must not look clean. See
``sandbox/TRUST.md``.

Enumerating imports by parsing is only sound because the gate bans
``__import__``, ``eval``, ``exec`` and ``compile`` and keeps ``importlib`` and
``runpy`` off the allowlist: with no dynamic import path, every import is a
literal statement and therefore visible in the syntax tree. If that ever stops
being true, this stops being complete, and nothing will look broken at the time.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from sandbox.validate import _import_allowed

# How many local files one closure may pull in. A cycle is already handled by
# the visited set; this bounds a pathological fan-out.
MAX_CLOSURE_FILES = 200


@dataclass
class Closure:
    """Everything one plugin is, and everything it reaches outside itself."""

    # Dotted module name (relative to the plugin's own directory) -> source text.
    # The plugin file itself is NOT in here; it is the entry point.
    modules: dict[str, str] = field(default_factory=dict)
    # Same keys, mapped to the file each came from — for hashing and display.
    files: dict[str, Path] = field(default_factory=dict)
    # Import name the sandbox gate refuses -> the modules that asked for it
    # (``""`` meaning the plugin file itself). This is the trust question.
    outside: dict[str, list[str]] = field(default_factory=dict)
    # Relative imports that resolved to no file. Not a security problem — the
    # import fails at runtime — but almost always a missing helper install.
    missing: list[str] = field(default_factory=list)
    # Files that could not be parsed at all.
    unreadable: list[str] = field(default_factory=list)

    @property
    def needs_trust(self) -> bool:
        """Whether this plugin can run sandboxed at all.

        Anything the gate refuses has to run in-process or not run, so this is
        exactly the question the user gets asked."""
        return bool(self.outside)

    def outside_names(self) -> list[str]:
        """The outside imports, sorted — the list a trust prompt shows."""
        return sorted(self.outside)


def _resolve_relative(current: str, level: int, module: str) -> str | None:
    """Resolve a relative import to a dotted name inside the closure.

    ``current`` is the importing module's own dotted name (``""`` for the plugin
    file). Standard Python semantics: level 1 is the importing module's package,
    each extra level goes one further up. Returns ``None`` when the import would
    climb above the plugin's own directory — that is outside the closure, and
    letting it resolve would silently widen what "this plugin" means.
    """
    parts = current.split(".") if current else []
    if parts:
        parts = parts[:-1]              # a module's package is its parent
    for _ in range(level - 1):
        if not parts:
            return None                 # climbed past the root
        parts.pop()
    if module:
        parts.extend(module.split("."))
    return ".".join(parts)


def _candidates(root: Path, dotted: str) -> list[Path]:
    """Where a dotted closure name could live on disk."""
    if not dotted:
        return []
    stem = root.joinpath(*dotted.split("."))
    return [stem.with_suffix(".py"), stem / "__init__.py"]


def build_closure(plugin_path: str | Path, source: str | None = None) -> Closure:
    """Trace one plugin: its local files, and everything it reaches outside.

    ``source`` overrides what is on disk for the entry file, so a caller that
    already has the text (or is checking a file mid-edit) need not re-read it.
    """
    plugin_path = Path(plugin_path)
    root = plugin_path.parent
    closure = Closure()

    try:
        entry_source = source if source is not None else plugin_path.read_text(encoding="utf-8")
    except OSError:
        closure.unreadable.append(str(plugin_path))
        return closure

    # (dotted name, source) still to walk. "" is the plugin file itself.
    pending: list[tuple[str, str]] = [("", entry_source)]
    seen: set[str] = {""}

    while pending:
        name, text = pending.pop()
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            closure.unreadable.append(name or str(plugin_path))
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if not _import_allowed(alias.name):
                        closure.outside.setdefault(alias.name, []).append(name)
                continue
            if not isinstance(node, ast.ImportFrom):
                continue

            if not node.level:
                if not _import_allowed(node.module or ""):
                    closure.outside.setdefault(node.module or "", []).append(name)
                continue

            # Relative: local to this plugin, so follow it.
            target = _resolve_relative(name, node.level, node.module or "")
            if target is None:
                closure.missing.append(f"{'.' * node.level}{node.module or ''}")
                continue

            # ``from .helpers import thing`` may name either a module or an
            # attribute of one, so try the submodule first and fall back.
            for candidate in ([f"{target}.{a.name}" for a in node.names] + [target]):
                if candidate in seen:
                    continue
                path = next((p for p in _candidates(root, candidate) if p.is_file()), None)
                if path is None:
                    continue
                if len(closure.modules) >= MAX_CLOSURE_FILES:
                    closure.missing.append(f"{candidate} (closure size limit)")
                    break
                try:
                    child_source = path.read_text(encoding="utf-8")
                except OSError:
                    closure.unreadable.append(candidate)
                    continue
                seen.add(candidate)
                closure.modules[candidate] = child_source
                closure.files[candidate] = path
                pending.append((candidate, child_source))
            else:
                if target not in seen and not any(
                        f"{target}.{a.name}" in seen for a in node.names):
                    closure.missing.append(f"{'.' * node.level}{node.module or ''}")

    # De-duplicate the "who asked" lists without losing order.
    for key, askers in closure.outside.items():
        closure.outside[key] = sorted(set(askers))
    return closure

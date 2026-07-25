"""AST validation for sandboxed tool code — reject before it runs.

The first line of defence (the child process import gate is the second). We
parse the tool source and reject:

- relative imports, and any import not on the allowlist,
- banned builtins (``eval``, ``exec``, ``open``, ``__import__``, …),
- introspection attributes that escape the sandbox (``__globals__``,
  ``__subclasses__``, ``f_back``, …).

The allowlist is stdlib-pure modules plus the few kernel imports a tool needs:
its base class (``plugins.BaseTool``, or the deprecated ``plugins.BaseSandboxTool``
shim) and ``effects.vocabulary`` (the request types it yields). None pulls a db,
socket, or filesystem handle into scope — the whole point is that the tool can
construct a request but never fulfil one.
"""

from __future__ import annotations

import ast

# Literal imports admitted exactly (no submodule fallback). The kernel modules
# are pure: BaseSandboxTool is the contract, effects.vocabulary is the request
# dataclasses, sandbox_kit is the pure tool-writing helpers (no I/O, no handles).
# urllib.parse is admitted (string munging, no sockets) while bare ``urllib`` is
# not — that would reach urllib.request.
_LITERAL_ALLOWED = {
    "plugins.BaseTool",          # the contract (a plugin sets contract = "effects")
    "plugins.BaseCommand",
    "plugins.BaseTask",
    "plugins.BaseSandboxTool",   # deprecated shim; kept until the store is converted
    "effects.vocabulary",
    "sandbox_kit",
    "urllib.parse",
}

# Top-level modules whose submodules are all admitted (stdlib, no I/O surface).
_TOP_ALLOWED = {
    "math", "random", "statistics", "itertools", "functools", "collections",
    "string", "textwrap", "re", "json", "datetime", "time", "calendar",
    "base64", "hashlib", "hmac", "decimal", "fractions", "uuid", "html",
    "unicodedata", "difflib", "enum", "dataclasses", "typing", "operator",
    "bisect", "heapq", "csv",
}

_BANNED_NAMES = {
    "__import__", "eval", "exec", "compile", "open",
    "globals", "locals", "vars", "input", "breakpoint",
    "exit", "quit", "help",
}

_BANNED_ATTRS = {
    "__class__", "__bases__", "__subclasses__", "__mro__",
    "__globals__", "__code__", "__closure__", "__dict__",
    "__builtins__", "__import__", "__getattribute__", "__subclasshook__",
    "__init_subclass__", "__reduce__", "__reduce_ex__",
    "f_globals", "f_locals", "f_back", "gi_frame", "cr_frame",
}


class SandboxValidationError(ValueError):
    """Raised when tool code fails AST validation. ``lineno`` locates it."""

    def __init__(self, message: str, lineno: int | None = None):
        """Initialize the validation error."""
        super().__init__(message)
        self.lineno = lineno


def _import_allowed(module: str) -> bool:
    """Literal allowlist with a stdlib top-level fallback (never for kernel pkgs)."""
    if module in _LITERAL_ALLOWED:
        return True
    if module.startswith(("plugins", "effects")):
        return False
    return module.split(".")[0] in _TOP_ALLOWED


def assert_valid(code: str) -> None:
    """Validate tool source. Raises :class:`SandboxValidationError` on the first
    problem found; returns ``None`` when the code is acceptable."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        raise SandboxValidationError(f"syntax error: {e.msg}", getattr(e, "lineno", None))

    for node in ast.walk(tree):
        # Imports ----------------------------------------------------------
        if isinstance(node, ast.Import):
            for alias in node.names:
                if not _import_allowed(alias.name):
                    raise SandboxValidationError(f"disallowed import: {alias.name}", node.lineno)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                raise SandboxValidationError("relative imports are not allowed", node.lineno)
            if not _import_allowed(node.module or ""):
                raise SandboxValidationError(f"disallowed import: {node.module}", node.lineno)
        # Banned builtin names --------------------------------------------
        elif isinstance(node, ast.Name):
            if node.id in _BANNED_NAMES:
                raise SandboxValidationError(f"use of banned name: {node.id}", node.lineno)
        # Banned attribute access -----------------------------------------
        elif isinstance(node, ast.Attribute):
            if node.attr in _BANNED_ATTRS:
                raise SandboxValidationError(f"access to banned attribute: {node.attr}", node.lineno)

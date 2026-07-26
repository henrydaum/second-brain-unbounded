"""Strict, data-only plugin manifest parsing.

The host may call this module while inspecting hostile bytes.  It therefore
uses ``tomllib`` only and never imports the artifact's Python modules.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

SCHEMA_VERSION = 1
MANIFEST_NAME = "plugin.toml"
HANDLER_KINDS = frozenset({
    "tool", "command", "task", "service", "frontend", "hook", "parser",
    "model_provider",
})
_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_RIGHT = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
_ENTRYPOINT = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")
_TOP_KEYS = frozenset({
    "schema_version", "id", "version", "runtime", "description", "handlers",
    "capabilities", "budgets",
})
_HANDLER_KEYS = frozenset({
    "kind", "name", "entrypoint", "description", "schema", "subscriptions",
    "persistent",
})
_CAPABILITY_KEYS = frozenset({
    "right", "resource", "destinations", "labels", "constraints",
})
_BUDGET_KEYS = frozenset({
    "memory_mb", "cpu_seconds", "wall_seconds", "max_output_bytes",
    "max_concurrency",
})


class ManifestError(ValueError):
    """The manifest is malformed or asks the host to guess."""


@dataclass(frozen=True)
class CapabilityPattern:
    """The maximum shape of one right an artifact may request."""

    right: str
    resource: str = "*"
    destinations: tuple[str, ...] = ()
    labels: tuple[str, ...] = ()
    constraints: Mapping[str, Any] = field(
        default_factory=lambda: MappingProxyType({}))

    def matches(self, right: str, selector: str, destination: str = "") -> bool:
        if self.right != right:
            return False
        if not _selector_contains(self.resource, selector):
            return False
        if destination and self.destinations:
            return any(_selector_contains(item, destination)
                       for item in self.destinations)
        return not destination or bool(self.destinations)


@dataclass(frozen=True)
class HandlerManifest:
    """One kernel-visible handler.  Its code is named, not loaded."""

    kind: str
    name: str
    entrypoint: str
    description: str = ""
    schema: Mapping[str, Any] = field(
        default_factory=lambda: MappingProxyType({}))
    subscriptions: tuple[str, ...] = ()
    persistent: bool = False


@dataclass(frozen=True)
class ResourceBudgets:
    memory_mb: int = 512
    cpu_seconds: int = 30
    wall_seconds: int = 30
    max_output_bytes: int = 8 * 1024 * 1024
    max_concurrency: int = 1


@dataclass(frozen=True)
class PluginManifest:
    """Immutable kernel-owned representation of ``plugin.toml``."""

    schema_version: int
    plugin_id: str
    version: str
    runtime: str
    description: str
    handlers: tuple[HandlerManifest, ...]
    capabilities: tuple[CapabilityPattern, ...]
    budgets: ResourceBudgets
    source_path: Path

    def handler(self, kind: str, name: str) -> HandlerManifest | None:
        return next((item for item in self.handlers
                     if item.kind == kind and item.name == name), None)

    def declares(self, right: str, selector: str,
                 destination: str = "") -> bool:
        return any(item.matches(right, selector, destination)
                   for item in self.capabilities)


def load_manifest(path: str | Path) -> PluginManifest:
    """Parse and validate a manifest without executing artifact code."""
    source = Path(path).resolve()
    try:
        raw = tomllib.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError(f"could not parse {source}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ManifestError("manifest root must be a TOML table")
    _reject_unknown(raw, _TOP_KEYS, "manifest")

    schema_version = _integer(raw.get("schema_version"), "schema_version", 1, 1)
    if schema_version != SCHEMA_VERSION:
        raise ManifestError(
            f"unsupported schema_version {schema_version}; expected {SCHEMA_VERSION}")
    plugin_id = _text(raw.get("id"), "id")
    if not _ID.fullmatch(plugin_id):
        raise ManifestError("id must be a lowercase dotted/dashed identifier")
    version = _text(raw.get("version"), "version")
    runtime = _text(raw.get("runtime", "python"), "runtime")
    if runtime != "python":
        raise ManifestError(f"unsupported runtime {runtime!r}")

    handlers_raw = raw.get("handlers")
    if not isinstance(handlers_raw, list) or not handlers_raw:
        raise ManifestError("handlers must be a non-empty array of tables")
    handlers = tuple(_handler(item, i) for i, item in enumerate(handlers_raw))
    identities = [(item.kind, item.name) for item in handlers]
    if len(identities) != len(set(identities)):
        raise ManifestError("handler kind/name pairs must be unique")

    capabilities_raw = raw.get("capabilities", [])
    if not isinstance(capabilities_raw, list):
        raise ManifestError("capabilities must be an array of tables")
    capabilities = tuple(
        _capability(item, i) for i, item in enumerate(capabilities_raw))

    budgets_raw = raw.get("budgets", {})
    if not isinstance(budgets_raw, dict):
        raise ManifestError("budgets must be a table")
    _reject_unknown(budgets_raw, _BUDGET_KEYS, "budgets")
    budgets = ResourceBudgets(
        memory_mb=_integer(budgets_raw.get("memory_mb", 512),
                           "budgets.memory_mb", 64, 32768),
        cpu_seconds=_integer(budgets_raw.get("cpu_seconds", 30),
                             "budgets.cpu_seconds", 1, 86400),
        wall_seconds=_integer(budgets_raw.get("wall_seconds", 30),
                              "budgets.wall_seconds", 1, 86400),
        max_output_bytes=_integer(
            budgets_raw.get("max_output_bytes", 8 * 1024 * 1024),
            "budgets.max_output_bytes", 1024, 256 * 1024 * 1024),
        max_concurrency=_integer(
            budgets_raw.get("max_concurrency", 1),
            "budgets.max_concurrency", 1, 128),
    )
    return PluginManifest(
        schema_version=schema_version,
        plugin_id=plugin_id,
        version=version,
        runtime=runtime,
        description=_text(raw.get("description", ""), "description",
                          allow_empty=True),
        handlers=handlers,
        capabilities=capabilities,
        budgets=budgets,
        source_path=source,
    )


def _handler(raw: Any, index: int) -> HandlerManifest:
    where = f"handlers[{index}]"
    if not isinstance(raw, dict):
        raise ManifestError(f"{where} must be a table")
    _reject_unknown(raw, _HANDLER_KEYS, where)
    kind = _text(raw.get("kind"), f"{where}.kind")
    if kind not in HANDLER_KINDS:
        raise ManifestError(f"{where}.kind is not a supported handler kind")
    name = _text(raw.get("name"), f"{where}.name")
    if not _ID.fullmatch(name):
        raise ManifestError(f"{where}.name is not a safe identifier")
    entrypoint = _text(raw.get("entrypoint"), f"{where}.entrypoint")
    if not _ENTRYPOINT.fullmatch(entrypoint):
        raise ManifestError(
            f"{where}.entrypoint must have the form package.module:function")
    schema = raw.get("schema", {})
    if not isinstance(schema, dict):
        raise ManifestError(f"{where}.schema must be a table")
    subscriptions = _strings(raw.get("subscriptions", []),
                             f"{where}.subscriptions")
    persistent = raw.get("persistent", False)
    if not isinstance(persistent, bool):
        raise ManifestError(f"{where}.persistent must be boolean")
    return HandlerManifest(
        kind=kind,
        name=name,
        entrypoint=entrypoint,
        description=_text(raw.get("description", ""), f"{where}.description",
                          allow_empty=True),
        schema=_freeze(schema),
        subscriptions=subscriptions,
        persistent=persistent,
    )


def _capability(raw: Any, index: int) -> CapabilityPattern:
    where = f"capabilities[{index}]"
    if not isinstance(raw, dict):
        raise ManifestError(f"{where} must be a table")
    _reject_unknown(raw, _CAPABILITY_KEYS, where)
    right = _text(raw.get("right"), f"{where}.right")
    if not _RIGHT.fullmatch(right):
        raise ManifestError(f"{where}.right must have the form domain.action")
    resource = _text(raw.get("resource", "*"), f"{where}.resource")
    destinations = _strings(raw.get("destinations", []),
                            f"{where}.destinations")
    labels = _strings(raw.get("labels", []), f"{where}.labels")
    constraints = raw.get("constraints", {})
    if not isinstance(constraints, dict):
        raise ManifestError(f"{where}.constraints must be a table")
    return CapabilityPattern(
        right=right,
        resource=resource,
        destinations=destinations,
        labels=labels,
        constraints=_freeze(constraints),
    )


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({str(k): _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _reject_unknown(raw: Mapping[str, Any], allowed: frozenset[str],
                    where: str) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ManifestError(f"{where} contains unknown keys: {unknown}")


def _text(value: Any, where: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ManifestError(f"{where} must be a non-empty string")
    return value.strip() if not allow_empty else value


def _strings(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
            not isinstance(item, str) or not item.strip() for item in value):
        raise ManifestError(f"{where} must be an array of non-empty strings")
    return tuple(item.strip() for item in value)


def _integer(value: Any, where: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ManifestError(f"{where} must be an integer")
    if value < minimum or value > maximum:
        raise ManifestError(f"{where} must be between {minimum} and {maximum}")
    return value


def _selector_contains(granted: str, requested: str) -> bool:
    """Conservative hierarchical selector matching.

    Selectors are slash-delimited logical names, not host paths.  Wildcards are
    accepted only as a complete suffix (``notes/*``), avoiding a second policy
    language with surprising glob semantics.
    """
    if granted == "*":
        return True
    granted = granted.rstrip("/")
    requested = requested.rstrip("/")
    if granted.endswith("/*"):
        prefix = granted[:-2].rstrip("/")
        return requested == prefix or requested.startswith(prefix + "/")
    return granted == requested


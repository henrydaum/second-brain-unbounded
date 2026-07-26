"""Data-only discovery for clean-break plugin packages."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

from plugins.proxy import Invoker, PluginProxy, ProxyRegistry
from security.artifacts import ArtifactError, PluginArtifact, build_artifact
from security.manifest import MANIFEST_NAME, ManifestError

logger = logging.getLogger("ManifestDiscovery")


def discover_artifacts(roots: Iterable[str | Path]) -> tuple[
        tuple[PluginArtifact, ...], tuple[str, ...]]:
    """Find immediate package directories containing ``plugin.toml``.

    It returns diagnostics instead of executing a fallback loader.
    """
    found: list[PluginArtifact] = []
    errors: list[str] = []
    seen_ids: set[str] = set()
    for raw_root in roots:
        root = Path(raw_root)
        if not root.is_dir():
            continue
        candidates = sorted({
            path.parent
            for pattern in (f"*/{MANIFEST_NAME}", f"*/*/{MANIFEST_NAME}")
            for path in root.glob(pattern)
        })
        if (root / MANIFEST_NAME).is_file():
            candidates.insert(0, root)
        for candidate in candidates:
            try:
                artifact = build_artifact(candidate)
            except (ArtifactError, ManifestError, OSError) as exc:
                errors.append(f"{candidate}: {exc}")
                continue
            if artifact.identity.plugin_id in seen_ids:
                errors.append(
                    f"{candidate}: duplicate plugin id "
                    f"{artifact.identity.plugin_id!r}")
                continue
            seen_ids.add(artifact.identity.plugin_id)
            found.append(artifact)
    return tuple(found), tuple(errors)


def activate_discovered(roots: Iterable[str | Path], registry: ProxyRegistry,
                        invoker: Invoker) -> tuple[
                            tuple[PluginProxy, ...], tuple[str, ...]]:
    activated: list[PluginProxy] = []
    artifacts, errors = discover_artifacts(roots)
    diagnostics = list(errors)
    for artifact in artifacts:
        try:
            staged = registry.stage(artifact, invoker)
            registry.activate(staged)
            activated.extend(staged)
        except Exception as exc:  # proxy validation only; no extension code ran
            diagnostics.append(f"{artifact.root}: {exc}")
    return tuple(activated), tuple(diagnostics)

"""Explicit in-process execution for digest-pinned TCB promotions."""

from __future__ import annotations

import asyncio
import importlib
import inspect
import sys
import threading
import uuid
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from plugin_sdk import InvocationContext, ResourceHandle
from security.artifacts import PluginArtifact
from security.broker import CapabilityBroker, LocalCapabilityTransport
from security.capabilities import AuthorityContext, ProvenanceChain
from security.capabilities import DataLabel


class TrustedRuntimeError(RuntimeError):
    pass


class TrustedArtifactRuntime:
    """Loads promoted code into the kernel.

    This provides capability-API semantic parity and audit, not containment.
    Promotion is checked by the composition root before this class is used.
    """

    _import_lock = threading.RLock()

    def __init__(self, broker: CapabilityBroker):
        self.broker = broker
        self._handlers: dict[tuple[str, str, str], object] = {}
        self._state_taint: dict[
            tuple[str, str, str], frozenset[DataLabel]] = {}

    async def invoker_for(self, artifact: PluginArtifact):
        if not artifact.verify():
            raise TrustedRuntimeError("promoted artifact failed digest verification")
        for handler in artifact.manifest.handlers:
            key = (artifact.identity.digest, handler.kind, handler.name)
            if key not in self._handlers:
                self._handlers[key] = await asyncio.to_thread(
                    self._load_handler, artifact, handler.entrypoint)

        async def invoke(_artifact, handler, arguments, invocation=None):
            if not artifact.verify():
                raise TrustedRuntimeError(
                    "promoted artifact changed after activation")
            options = invocation or {}
            authority = options.get("authority") or AuthorityContext(
                artifact_digest=artifact.identity.digest,
                principal="agent",
                provenance=ProvenanceChain("agent").enter(
                    artifact.identity.digest,
                    f"{handler.kind}:{handler.name}"),
            )
            key = (artifact.identity.digest, handler.kind, handler.name)
            state_taint = self._state_taint.get(
                key, frozenset({DataLabel.PUBLIC}))
            authority = replace(
                authority,
                taint=frozenset((*authority.taint, *state_taint)),
            )
            resources = {
                alias: ResourceHandle(
                    token=str(item["token"]),
                    selector=str(item["selector"]),
                )
                for alias, item in dict(options.get("resources") or {}).items()
            }
            invocation_id = uuid.uuid4().hex
            transport = LocalCapabilityTransport(
                self.broker,
                invocation_id=invocation_id,
                manifest=artifact.manifest,
                authority=authority,
            )
            context = InvocationContext(transport, resources=resources)
            function = self._handlers[key]
            try:
                result = function(context, dict(arguments))
                if not inspect.isawaitable(result):
                    raise TrustedRuntimeError(
                        "clean SDK handlers must be async functions")
                return await result
            finally:
                self._state_taint[key] = frozenset((
                    *state_taint,
                    *self.broker.invocation_taint(
                        invocation_id, authority.taint),
                ))
                self.broker.finish_invocation(invocation_id)

        return invoke

    @classmethod
    def _load_handler(cls, artifact: PluginArtifact, entrypoint: str):
        module_name, function_name = entrypoint.split(":", 1)
        source = _module_source(artifact.root, module_name)
        if source is None:
            raise TrustedRuntimeError(
                f"entrypoint module is absent from artifact: {module_name}")
        with cls._import_lock, _artifact_import(artifact.root, module_name):
            module = importlib.import_module(module_name)
            loaded_from = Path(module.__file__).resolve()
            if loaded_from != source.resolve():
                raise TrustedRuntimeError(
                    "entrypoint resolved outside the promoted artifact")
            function = getattr(module, function_name, None)
            if not callable(function):
                raise TrustedRuntimeError(
                    f"entrypoint is not callable: {entrypoint}")
            return function


def _module_source(root: Path, module_name: str) -> Path | None:
    relative = Path(*module_name.split("."))
    module_file = root / relative.with_suffix(".py")
    package_file = root / relative / "__init__.py"
    if module_file.is_file():
        return module_file
    if package_file.is_file():
        return package_file
    return None


@contextmanager
def _artifact_import(root: Path, module_name: str):
    """Temporarily prioritize the artifact while preserving host modules."""
    prefixes = {
        ".".join(module_name.split(".")[:index])
        for index in range(1, len(module_name.split(".")) + 1)
    }
    displaced = {
        name: module for name, module in list(sys.modules.items())
        if any(name == prefix or name.startswith(prefix + ".")
               for prefix in prefixes)
    }
    for name in displaced:
        sys.modules.pop(name, None)
    sys.path.insert(0, str(root))
    prior_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        yield
    finally:
        sys.dont_write_bytecode = prior_bytecode
        try:
            sys.path.remove(str(root))
        except ValueError:
            pass
        for name, module in list(sys.modules.items()):
            path = getattr(module, "__file__", None)
            if path is not None:
                try:
                    if Path(path).resolve().is_relative_to(root.resolve()):
                        sys.modules.pop(name, None)
                except (OSError, ValueError):
                    pass
        sys.modules.update(displaced)

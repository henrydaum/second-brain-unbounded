"""Kernel filesystem adapters using opaque bindings and durable inverses."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from security.broker import PreparedEffect
from security.capabilities import (
    AuthorityContext,
    CapabilityRequest,
    DataLabel,
    MediationFacts,
    ResourceRegistry,
)
from security.file_journal import DurableFileJournal
from security.manifest import _selector_contains


class FileCapabilityAdapter:
    def __init__(self, resources: ResourceRegistry,
                 journal: DurableFileJournal, *,
                 max_read_bytes: int = 16 * 1024 * 1024,
                 max_write_bytes: int = 16 * 1024 * 1024,
                 max_list_entries: int = 10_000):
        self.resources = resources
        self.journal = journal
        self.max_read_bytes = max(1024, int(max_read_bytes))
        self.max_write_bytes = max(1024, int(max_write_bytes))
        self.max_list_entries = max(1, int(max_list_entries))

    def prepare_read(self, authority: AuthorityContext,
                     payload: Mapping[str, Any]) -> PreparedEffect:
        request, target = self._target(authority, "files.read", payload)
        if target is None:
            return _denied(request)
        encoding = str(payload.get("encoding") or "utf-8")

        def enact():
            with target.open("rb") as stream:
                raw = stream.read(self.max_read_bytes + 1)
            if len(raw) > self.max_read_bytes:
                raise ValueError(
                    f"file exceeds {self.max_read_bytes} read bytes")
            return raw.decode(encoding)

        return PreparedEffect(
            request=request,
            facts=MediationFacts(resource_exists=target.is_file()),
            enact=enact,
        )

    def prepare_list(self, authority: AuthorityContext,
                     payload: Mapping[str, Any]) -> PreparedEffect:
        request, target = self._target(authority, "files.list", payload)
        if target is None:
            return _denied(request)
        recursive = payload.get("recursive", False)
        if not isinstance(recursive, bool):
            raise ValueError("files.list recursive must be boolean")

        def enact():
            if not target.is_dir():
                raise FileNotFoundError("filesystem resource is not a directory")
            root = target.resolve()
            iterator = root.rglob("*") if recursive else root.iterdir()
            rows = []
            for item in iterator:
                if len(rows) >= self.max_list_entries:
                    raise ValueError(
                        f"file listing exceeds {self.max_list_entries} entries")
                relative = item.relative_to(root).as_posix()
                info = item.lstat()
                rows.append({
                    "name": relative,
                    "kind": (
                        "symlink" if item.is_symlink()
                        else "directory" if item.is_dir()
                        else "file" if item.is_file()
                        else "other"),
                    "size": int(info.st_size),
                    "modified_ns": int(info.st_mtime_ns),
                })
            return rows

        return PreparedEffect(
            request=request,
            facts=MediationFacts(resource_exists=target.is_dir()),
            enact=enact,
        )

    def prepare_stat(self, authority: AuthorityContext,
                     payload: Mapping[str, Any]) -> PreparedEffect:
        request, target = self._target(authority, "files.stat", payload)
        if target is None:
            return _denied(request)

        def enact():
            info = target.lstat()
            return {
                "kind": (
                    "symlink" if target.is_symlink()
                    else "directory" if target.is_dir()
                    else "file" if target.is_file()
                    else "other"),
                "size": int(info.st_size),
                "modified_ns": int(info.st_mtime_ns),
            }

        return PreparedEffect(
            request=request,
            facts=MediationFacts(resource_exists=target.exists()),
            enact=enact,
        )

    def prepare_write(self, authority: AuthorityContext,
                      payload: Mapping[str, Any]) -> PreparedEffect:
        request, target = self._target(authority, "files.write", payload)
        if target is None:
            return _denied(request)
        content = payload.get("content")
        if not isinstance(content, str):
            raise ValueError("files.write content must be text")
        encoding = str(payload.get("encoding") or "utf-8")
        raw = content.encode(encoding)
        if len(raw) > self.max_write_bytes:
            raise ValueError(
                f"file content exceeds {self.max_write_bytes} write bytes")
        mutation = self.journal.prepare(target)
        return PreparedEffect(
            request=request,
            facts=MediationFacts(
                undo_ready=True, resource_exists=mutation.existed),
            enact=lambda: mutation.write(raw),
            abort=mutation.abort,
        )

    def prepare_delete(self, authority: AuthorityContext,
                       payload: Mapping[str, Any]) -> PreparedEffect:
        request, target = self._target(authority, "files.delete", payload)
        if target is None:
            return _denied(request)
        mutation = self.journal.prepare(target)
        return PreparedEffect(
            request=request,
            facts=MediationFacts(
                undo_ready=True, resource_exists=mutation.existed),
            enact=mutation.delete,
            abort=mutation.abort,
        )

    def prepare_move(self, authority: AuthorityContext,
                     payload: Mapping[str, Any]) -> PreparedEffect:
        request, source = self._target(authority, "files.move", payload)
        if source is None:
            return _denied(request)
        destination_selector = payload.get("destination_selector")
        if not isinstance(destination_selector, str):
            raise ValueError("destination_selector must be a string")
        _destination_request, destination = self._target(
            authority,
            "files.move",
            {
                "resource": payload.get("resource"),
                "selector": destination_selector,
            },
        )
        if destination is None:
            return _denied(request)
        mutation = self.journal.prepare_move(source, destination)
        return PreparedEffect(
            request=request,
            facts=MediationFacts(undo_ready=True, resource_exists=True),
            enact=mutation.move,
            abort=mutation.abort,
        )

    def _target(self, authority: AuthorityContext, right: str,
                payload: Mapping[str, Any]
                ) -> tuple[CapabilityRequest, Path | None]:
        token = payload.get("resource")
        selector = payload.get("selector")
        if not isinstance(token, str) or not isinstance(selector, str):
            raise ValueError("resource and selector must be strings")
        ref = self.resources.resolve(token)
        if ref is None:
            return CapabilityRequest(right, token, selector), None
        if ref.artifact_digest != authority.artifact_digest:
            return CapabilityRequest(right, token, selector), None
        binding = self.resources.binding(token)
        if not isinstance(binding, Path):
            raise ValueError("filesystem resource has no path binding")
        if not _selector_contains(ref.selector, selector):
            return CapabilityRequest(right, token, selector), None
        relative = _relative_selector(ref.selector, selector)
        target = (binding / Path(*relative.split("/"))).resolve()
        root = binding.resolve()
        if target != root and root not in target.parents:
            raise PermissionError("resolved target escaped resource binding")
        labels = frozenset(ref.labels) or frozenset({DataLabel.PUBLIC})
        return CapabilityRequest(
            right=right,
            resource_token=token,
            selector=selector,
            payload_labels=labels,
        ), target


def _denied(request: CapabilityRequest) -> PreparedEffect:
    return PreparedEffect(
        request=request,
        facts=MediationFacts(resource_exists=False),
        enact=lambda: None,
    )


def _relative_selector(granted: str, requested: str) -> str:
    granted = granted.rstrip("/")
    requested = requested.rstrip("/")
    if granted.endswith("/*"):
        prefix = granted[:-2].rstrip("/")
        if requested == prefix:
            return ""
        return requested[len(prefix) + 1:]
    if granted == requested:
        return ""
    raise PermissionError("selector is outside the resource binding")

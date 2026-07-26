"""Broker-owned attachment materialization and opaque output handles."""

from __future__ import annotations

import os
import secrets
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from security.broker import PreparedEffect
from security.capabilities import (
    AuthorityContext,
    CapabilityRequest,
    MediationFacts,
    ResourceRegistry,
)
from security.manifest import _selector_contains


class OutputError(RuntimeError):
    pass


@dataclass(frozen=True)
class AttachmentRef:
    token: str
    artifact_digest: str
    principal: str
    path: Path
    user_id: int | None
    session_key: str | None
    conversation_id: int | None
    expires_at: float


class AttachmentRegistry:
    def __init__(self, root: str | Path, *, lifetime_seconds: int = 3600):
        self.root = Path(root)
        self.lifetime_seconds = max(60, int(lifetime_seconds))
        self._items: dict[str, AttachmentRef] = {}
        self._lock = threading.RLock()

    def materialize(
        self,
        source: Path,
        authority: AuthorityContext,
        *,
        max_bytes: int,
    ) -> AttachmentRef:
        size = source.stat().st_size
        if size > max_bytes:
            raise OutputError(f"attachment exceeds {max_bytes} bytes")
        token = secrets.token_urlsafe(32)
        directory = self.root / token
        directory.mkdir(parents=True, exist_ok=False)
        destination = directory / source.name
        fd, raw_temp = tempfile.mkstemp(
            prefix=source.name + ".", suffix=".tmp", dir=directory)
        try:
            copied = 0
            with source.open("rb") as inp, os.fdopen(fd, "wb") as out:
                while True:
                    chunk = inp.read(min(1024 * 1024, max_bytes + 1 - copied))
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > max_bytes:
                        raise OutputError(
                            f"attachment exceeds {max_bytes} bytes")
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            os.replace(raw_temp, destination)
            ref = AttachmentRef(
                token=token,
                artifact_digest=authority.artifact_digest,
                principal=authority.principal,
                path=destination,
                user_id=authority.user_id,
                session_key=authority.session_key,
                conversation_id=authority.conversation_id,
                expires_at=time.time() + self.lifetime_seconds,
            )
            with self._lock:
                self._items[token] = ref
            return ref
        except Exception:
            try:
                Path(raw_temp).unlink()
            except FileNotFoundError:
                pass
            try:
                directory.rmdir()
            except OSError:
                pass
            raise

    def resolve(
        self,
        token: str,
        authority: AuthorityContext,
    ) -> AttachmentRef | None:
        with self._lock:
            ref = self._items.get(token)
            if ref is None:
                return None
            if time.time() >= ref.expires_at:
                self._items.pop(token, None)
                shutil.rmtree(ref.path.parent, ignore_errors=True)
                return None
            if (ref.artifact_digest != authority.artifact_digest
                    or ref.principal != authority.principal
                    or ref.user_id != authority.user_id
                    or ref.session_key != authority.session_key
                    or ref.conversation_id != authority.conversation_id):
                return None
            return ref

    def revoke(self, token: str) -> bool:
        with self._lock:
            ref = self._items.pop(token, None)
        if ref is None:
            return False
        shutil.rmtree(ref.path.parent, ignore_errors=True)
        return True


class OutputCapabilityAdapter:
    def __init__(
        self,
        resources: ResourceRegistry,
        attachments: AttachmentRegistry,
        *,
        max_bytes: int = 64 * 1024 * 1024,
    ):
        self.resources = resources
        self.attachments = attachments
        self.max_bytes = max(1024, int(max_bytes))

    def prepare_attach(
        self,
        authority: AuthorityContext,
        payload: Mapping[str, Any],
    ) -> PreparedEffect:
        token = payload.get("resource")
        selector = payload.get("selector")
        if not isinstance(token, str) or not isinstance(selector, str):
            raise OutputError("resource and selector must be strings")
        ref = self.resources.resolve(token)
        if ref is None or ref.artifact_digest != authority.artifact_digest:
            target = Path("__denied__")
        else:
            binding = self.resources.binding(token)
            if not isinstance(binding, Path):
                raise OutputError("attachment resource has no path binding")
            if not _selector_contains(ref.selector, selector):
                target = Path("__denied__")
            else:
                relative = _relative_selector(ref.selector, selector)
                root = binding.resolve()
                target = (root / Path(*relative.split("/"))).resolve()
                if target != root and root not in target.parents:
                    raise OutputError("attachment escaped resource binding")
        request = CapabilityRequest(
            right="outputs.attach",
            resource_token=token,
            selector=selector,
            payload_labels=ref.labels if ref is not None else frozenset(),
        )

        def enact():
            if not target.is_file():
                raise OutputError("attachment source is not a file")
            attachment = self.attachments.materialize(
                target, authority, max_bytes=self.max_bytes)
            return {
                "attachment": attachment.token,
                "name": attachment.path.name,
                "size": attachment.path.stat().st_size,
            }

        return PreparedEffect(
            request=request,
            facts=MediationFacts(resource_exists=target.is_file()),
            enact=enact,
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
    raise OutputError("selector is outside the resource binding")

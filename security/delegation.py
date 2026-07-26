"""Attenuation-only delegation for plugin calls and background work."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from security.artifacts import PluginArtifact
from security.capabilities import (
    AuthorityContext,
    ResourceRef,
    ResourceRegistry,
)
from security.manifest import HandlerManifest


@dataclass(frozen=True)
class DelegatedResource:
    parent_token: str
    rights: frozenset[str]
    selector: str | None = None
    expires_at: float | None = None


@dataclass(frozen=True)
class DelegatedInvocation:
    authority: AuthorityContext
    resources: tuple[ResourceRef, ...]


class DelegationService:
    """Construct child authority entirely from kernel-known parent state."""

    def __init__(self, resources: ResourceRegistry):
        self.resources = resources

    def delegate(
        self,
        *,
        parent: AuthorityContext,
        child_artifact: PluginArtifact,
        child_handler: HandlerManifest,
        requested: Iterable[DelegatedResource],
        unattended: bool = False,
    ) -> DelegatedInvocation:
        if parent.provenance.current_digest != parent.artifact_digest:
            raise PermissionError("parent provenance is not current")
        if child_handler not in child_artifact.manifest.handlers:
            raise PermissionError("handler does not belong to child artifact")

        plans: list[tuple[DelegatedResource, ResourceRef, str]] = []
        for request in requested:
            source = self.resources.resolve(request.parent_token)
            if source is None:
                raise PermissionError("delegated resource is absent or expired")
            self._verify_parent_owns(source, parent)
            selector = request.selector or source.selector
            for right in request.rights:
                if not child_artifact.manifest.declares(
                        right, selector):
                    raise PermissionError(
                        f"child manifest does not declare {right} on {selector}")
            plans.append((request, source, selector))

        created: list[ResourceRef] = []
        try:
            for request, _source, selector in plans:
                created.append(self.resources.attenuate(
                    request.parent_token,
                    artifact_digest=child_artifact.identity.digest,
                    rights=request.rights,
                    selector=selector,
                    expires_at=request.expires_at,
                ))
        except Exception:
            for ref in created:
                self.resources.revoke(ref.token)
            raise

        digest = child_artifact.identity.digest
        authority = AuthorityContext(
            artifact_digest=digest,
            principal=parent.principal,
            provenance=parent.provenance.enter(
                digest, f"{child_handler.kind}:{child_handler.name}"),
            user_id=parent.user_id,
            session_key=parent.session_key,
            conversation_id=parent.conversation_id,
            unattended=parent.unattended or unattended,
            taint=parent.taint,
        )
        return DelegatedInvocation(authority, tuple(created))

    @staticmethod
    def _verify_parent_owns(
        resource: ResourceRef,
        parent: AuthorityContext,
    ) -> None:
        if resource.artifact_digest != parent.artifact_digest:
            raise PermissionError("resource is not held by the parent artifact")
        if resource.principal != parent.principal:
            raise PermissionError("resource principal differs from parent")
        if resource.user_id is not None and resource.user_id != parent.user_id:
            raise PermissionError("resource user differs from parent")
        if (resource.session_key is not None
                and resource.session_key != parent.session_key):
            raise PermissionError("resource session differs from parent")
        if (resource.conversation_id is not None
                and resource.conversation_id != parent.conversation_id):
            raise PermissionError("resource conversation differs from parent")

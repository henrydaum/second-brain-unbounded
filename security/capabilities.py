"""The kernel reference monitor's authority and policy model."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Callable, Iterable

from security.manifest import PluginManifest, _selector_contains
from security.vocabulary import EffectKind, descriptor


class DataLabel(IntEnum):
    PUBLIC = 0
    USER_PRIVATE = 1
    SYSTEM_SENSITIVE = 2
    SECRET = 3


@dataclass(frozen=True)
class ProvenanceFrame:
    artifact_digest: str
    handler: str


@dataclass(frozen=True)
class ProvenanceChain:
    principal: str
    frames: tuple[ProvenanceFrame, ...] = ()

    @property
    def current_digest(self) -> str:
        return self.frames[-1].artifact_digest if self.frames else ""

    def enter(self, artifact_digest: str, handler: str) -> "ProvenanceChain":
        if any(item.artifact_digest == artifact_digest
               and item.handler == handler for item in self.frames):
            raise ValueError("provenance cycle")
        return replace(
            self,
            frames=(*self.frames, ProvenanceFrame(artifact_digest, handler)),
        )


@dataclass(frozen=True)
class ResourceRef:
    """Kernel-held authority.  Only ``token`` crosses into a worker."""

    token: str
    artifact_digest: str
    principal: str
    rights: frozenset[str]
    selector: str
    alias: str = ""
    labels: frozenset[DataLabel] = frozenset({DataLabel.PUBLIC})
    user_id: int | None = None
    session_key: str | None = None
    conversation_id: int | None = None
    expires_at: float | None = None
    delegation_depth: int = 0

    def expired(self, now: float | None = None) -> bool:
        return self.expires_at is not None and (
            time.time() if now is None else now) >= self.expires_at


class ResourceRegistry:
    """Issues and resolves unforgeable opaque resource references."""

    def __init__(self):
        self._items: dict[str, ResourceRef] = {}
        self._bindings: dict[str, object] = {}
        self._lock = threading.RLock()

    def issue(self, *, artifact_digest: str, principal: str,
              rights: Iterable[str], selector: str,
              alias: str = "",
              labels: Iterable[DataLabel] = (DataLabel.PUBLIC,),
              user_id: int | None = None, session_key: str | None = None,
              conversation_id: int | None = None,
              expires_at: float | None = None,
              delegation_depth: int = 0,
              binding: object | None = None) -> ResourceRef:
        rights_set = frozenset(rights)
        if not artifact_digest or not principal or not rights_set or not selector:
            raise ValueError(
                "artifact_digest, principal, rights, and selector are required")
        token = secrets.token_urlsafe(32)
        ref = ResourceRef(
            token=token,
            artifact_digest=artifact_digest,
            principal=principal,
            rights=rights_set,
            selector=selector,
            alias=alias,
            labels=frozenset(labels) or frozenset({DataLabel.PUBLIC}),
            user_id=user_id,
            session_key=session_key,
            conversation_id=conversation_id,
            expires_at=expires_at,
            delegation_depth=max(0, int(delegation_depth)),
        )
        with self._lock:
            self._items[token] = ref
            if binding is not None:
                self._bindings[token] = binding
        return ref

    def resolve(self, token: str) -> ResourceRef | None:
        with self._lock:
            item = self._items.get(token)
            if item is None or item.expired():
                self._items.pop(token, None)
                self._bindings.pop(token, None)
                return None
            return item

    def revoke(self, token: str) -> bool:
        with self._lock:
            self._bindings.pop(token, None)
            return self._items.pop(token, None) is not None

    def binding(self, token: str) -> object | None:
        """Return the kernel object behind a live token.

        The object is never serialized and is intentionally absent from
        ``ResourceRef``.
        """
        with self._lock:
            if self.resolve(token) is None:
                self._bindings.pop(token, None)
                return None
            return self._bindings.get(token)

    def attenuate(self, parent_token: str, *, artifact_digest: str,
                  rights: Iterable[str], selector: str | None = None,
                  expires_at: float | None = None) -> ResourceRef:
        parent = self.resolve(parent_token)
        if parent is None:
            raise PermissionError("parent resource is absent or expired")
        if parent.delegation_depth <= 0:
            raise PermissionError("resource cannot be delegated further")
        narrowed = frozenset(rights)
        if not narrowed or not narrowed.issubset(parent.rights):
            raise PermissionError("delegated rights must be a non-empty subset")
        child_selector = selector or parent.selector
        if not _selector_contains(parent.selector, child_selector):
            raise PermissionError("delegated selector is broader than parent")
        child_expiry = expires_at
        if parent.expires_at is not None and (
                child_expiry is None or child_expiry > parent.expires_at):
            child_expiry = parent.expires_at
        return self.issue(
            artifact_digest=artifact_digest,
            principal=parent.principal,
            rights=narrowed,
            selector=child_selector,
            alias=parent.alias,
            labels=parent.labels,
            user_id=parent.user_id,
            session_key=parent.session_key,
            conversation_id=parent.conversation_id,
            expires_at=child_expiry,
            delegation_depth=parent.delegation_depth - 1,
            binding=self.binding(parent_token),
        )

    def for_authority(self, authority: "AuthorityContext") -> tuple[ResourceRef, ...]:
        with self._lock:
            out = []
            for token in list(self._items):
                ref = self.resolve(token)
                if ref is None:
                    continue
                if ref.artifact_digest != authority.artifact_digest:
                    continue
                if ref.principal != authority.principal:
                    continue
                if ref.user_id is not None and ref.user_id != authority.user_id:
                    continue
                if (ref.session_key is not None
                        and ref.session_key != authority.session_key):
                    continue
                if (ref.conversation_id is not None
                        and ref.conversation_id != authority.conversation_id):
                    continue
                out.append(ref)
            return tuple(out)


@dataclass
class GrantLease:
    lease_id: str
    artifact_digest: str
    principal: str
    right: str
    resource_selector: str
    allowed_labels: frozenset[DataLabel]
    destination: str = ""
    user_id: int | None = None
    session_key: str | None = None
    conversation_id: int | None = None
    unattended: bool = False
    expires_at: float | None = None
    remaining_uses: int | None = 1
    provenance_digests: tuple[str, ...] = ()
    revoked: bool = False

    @classmethod
    def create(cls, **kwargs) -> "GrantLease":
        return cls(lease_id=secrets.token_urlsafe(24), **kwargs)

    def active(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return (
            not self.revoked
            and (self.expires_at is None or now < self.expires_at)
            and (self.remaining_uses is None or self.remaining_uses > 0)
        )


class LeaseStore:
    """Thread-safe lease store with atomic consume semantics."""

    def __init__(self):
        self._leases: dict[str, GrantLease] = {}
        self._lock = threading.RLock()

    def add(self, lease: GrantLease) -> None:
        with self._lock:
            if lease.lease_id in self._leases:
                raise ValueError("duplicate lease id")
            self._leases[lease.lease_id] = lease

    def revoke(self, lease_id: str) -> bool:
        with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None:
                return False
            lease.revoked = True
            return True

    def find_and_consume(
        self,
        *,
        authority: "AuthorityContext",
        request: "CapabilityRequest",
        labels: frozenset[DataLabel],
    ) -> GrantLease | None:
        digests = tuple(item.artifact_digest for item in authority.provenance.frames)
        with self._lock:
            for lease in self._leases.values():
                if not lease.active():
                    continue
                if lease.artifact_digest != authority.artifact_digest:
                    continue
                if lease.principal != authority.principal:
                    continue
                if lease.right != request.right:
                    continue
                if not _selector_contains(
                        lease.resource_selector, request.selector):
                    continue
                if request.destination and not _selector_contains(
                        lease.destination, request.destination):
                    continue
                if not labels.issubset(lease.allowed_labels):
                    continue
                if lease.user_id is not None and lease.user_id != authority.user_id:
                    continue
                if (lease.session_key is not None
                        and lease.session_key != authority.session_key):
                    continue
                if (lease.conversation_id is not None
                        and lease.conversation_id != authority.conversation_id):
                    continue
                if authority.unattended and not lease.unattended:
                    continue
                if lease.provenance_digests and lease.provenance_digests != digests:
                    continue
                if lease.remaining_uses is not None:
                    lease.remaining_uses -= 1
                return lease
        return None


@dataclass(frozen=True)
class AuthorityContext:
    """Invocation identity populated exclusively by the kernel."""

    artifact_digest: str
    principal: str
    provenance: ProvenanceChain
    user_id: int | None = None
    session_key: str | None = None
    conversation_id: int | None = None
    unattended: bool = False
    taint: frozenset[DataLabel] = frozenset({DataLabel.PUBLIC})


@dataclass(frozen=True)
class CapabilityRequest:
    """Untrusted request fields supplied by a plugin."""

    right: str
    resource_token: str = ""
    selector: str = ""
    destination: str = ""
    payload_labels: frozenset[DataLabel] = frozenset()


@dataclass(frozen=True)
class MediationFacts:
    """Facts established by the broker, never accepted from the plugin."""

    undo_ready: bool = False
    destination_verified: bool = False
    resource_exists: bool = True
    observed_labels: frozenset[DataLabel] = frozenset()


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    effect: EffectKind | None = None
    lease_id: str = ""
    labels: frozenset[DataLabel] = frozenset()
    observes: bool = False


class PolicyEngine:
    """Small reference monitor decision function."""

    def __init__(self, resources: ResourceRegistry, leases: LeaseStore,
                 audit: Callable[[AuthorityContext, CapabilityRequest,
                                  PolicyDecision], None] | None = None):
        self.resources = resources
        self.leases = leases
        self.audit = audit

    def decide(self, manifest: PluginManifest, authority: AuthorityContext,
               request: CapabilityRequest,
               facts: MediationFacts = MediationFacts()) -> PolicyDecision:
        decision = self._decide(manifest, authority, request, facts)
        if self.audit is not None:
            self.audit(authority, request, decision)
        return decision

    def _decide(self, manifest: PluginManifest, authority: AuthorityContext,
                request: CapabilityRequest,
                facts: MediationFacts) -> PolicyDecision:
        cap = descriptor(request.right)
        if cap is None:
            return PolicyDecision(False, "right is not in the closed vocabulary")
        if not authority.artifact_digest:
            return PolicyDecision(
                False, "invocation has no artifact identity", cap.effect,
                observes=cap.observes)
        if authority.provenance.principal != authority.principal:
            return PolicyDecision(
                False, "principal/provenance mismatch", cap.effect,
                observes=cap.observes)
        if (authority.provenance.current_digest
                and authority.provenance.current_digest != authority.artifact_digest):
            return PolicyDecision(
                False, "current provenance frame mismatch", cap.effect,
                observes=cap.observes)
        if not manifest.declares(
                request.right, request.selector, request.destination):
            return PolicyDecision(
                False, "request exceeds manifest ceiling", cap.effect,
                observes=cap.observes)

        labels = frozenset((
            *authority.taint,
            *request.payload_labels,
            *facts.observed_labels,
        ))
        resource = None
        if request.resource_token:
            resource = self.resources.resolve(request.resource_token)
            refusal = self._check_resource(resource, authority, request)
            if refusal:
                return PolicyDecision(
                    False, refusal, cap.effect, labels=labels,
                    observes=cap.observes)
            labels = frozenset((*labels, *resource.labels))
        elif cap.resource_required:
            return PolicyDecision(
                False, "local operation requires an opaque resource reference",
                cap.effect, labels=labels, observes=cap.observes)

        sensitive = max(labels, default=DataLabel.PUBLIC) > DataLabel.PUBLIC
        reversible = (
            cap.mutates
            and cap.may_be_reversible
            and facts.undo_ready
        )
        requires_lease = (
            sensitive
            or cap.egresses
            or cap.administers
            or (cap.mutates and not reversible)
            or cap.autonomous
            or authority.unattended
        )
        if not requires_lease:
            return PolicyDecision(
                True, "authorized resource and prompt-free safe effect",
                cap.effect, labels=labels, observes=cap.observes)

        lease = self.leases.find_and_consume(
            authority=authority, request=request, labels=labels)
        if lease is None:
            return PolicyDecision(
                False, "no matching active scoped lease", cap.effect,
                labels=labels, observes=cap.observes)
        return PolicyDecision(
            True, "authorized by scoped lease", cap.effect,
            lease_id=lease.lease_id, labels=labels,
            observes=cap.observes)

    @staticmethod
    def _check_resource(resource: ResourceRef | None,
                        authority: AuthorityContext,
                        request: CapabilityRequest) -> str:
        if resource is None:
            return "resource reference is absent, expired, or revoked"
        if resource.artifact_digest != authority.artifact_digest:
            return "resource belongs to a different artifact"
        if resource.principal != authority.principal:
            return "resource belongs to a different principal"
        if request.right not in resource.rights:
            return "resource does not grant the requested right"
        if not _selector_contains(resource.selector, request.selector):
            return "requested selector exceeds resource authority"
        if resource.user_id is not None and resource.user_id != authority.user_id:
            return "resource belongs to a different user"
        if (resource.session_key is not None
                and resource.session_key != authority.session_key):
            return "resource belongs to a different session"
        if (resource.conversation_id is not None
                and resource.conversation_id != authority.conversation_id):
            return "resource belongs to a different conversation"
        return ""


EffectKind = EffectKind

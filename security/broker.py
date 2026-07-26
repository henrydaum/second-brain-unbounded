"""Side-effect ordering for the capability reference monitor."""

from __future__ import annotations

import inspect
from dataclasses import dataclass, replace
from typing import Any, Awaitable, Callable, Mapping

from security.capabilities import (
    AuthorityContext,
    CapabilityRequest,
    DataLabel,
    MediationFacts,
    PolicyDecision,
    PolicyEngine,
)
from security.manifest import PluginManifest


class BrokerError(RuntimeError):
    pass


@dataclass(frozen=True)
class PreparedEffect:
    """Validated but not yet enacted operation.

    ``prepare`` may parse and resolve names, but must not produce an externally
    visible effect.  This split makes "denied operations have no effect"
    structural.
    """

    request: CapabilityRequest
    facts: MediationFacts
    enact: Callable[[], Any | Awaitable[Any]]
    abort: Callable[[], Any | Awaitable[Any]] | None = None


Prepare = Callable[
    [AuthorityContext, Mapping[str, Any]], PreparedEffect | Awaitable[PreparedEffect]]


class CapabilityBroker:
    def __init__(self, policy: PolicyEngine, approval_provider=None):
        self.policy = policy
        self.approval_provider = approval_provider
        self._adapters: dict[str, Prepare] = {}
        self._taint: dict[str, frozenset[DataLabel]] = {}

    def register(self, right: str, prepare: Prepare) -> None:
        if right in self._adapters:
            raise ValueError(f"adapter already registered for {right}")
        self._adapters[right] = prepare

    async def fulfill(self, *, invocation_id: str, manifest: PluginManifest,
                      authority: AuthorityContext, right: str,
                      payload: Mapping[str, Any]) -> Any:
        adapter = self._adapters.get(right)
        if adapter is None:
            raise BrokerError(f"no kernel adapter for {right}")
        current_taint = self._taint.get(invocation_id, authority.taint)
        authority = replace(authority, taint=current_taint)
        prepared = adapter(authority, dict(payload))
        if inspect.isawaitable(prepared):
            prepared = await prepared
        if prepared.request.right != right:
            raise BrokerError("adapter prepared a different capability right")
        decision = self.policy.decide(
            manifest, authority, prepared.request, prepared.facts)
        if (not decision.allowed
                and decision.reason == "no matching active scoped lease"
                and self.approval_provider is not None):
            lease = self.approval_provider(
                manifest, authority, prepared.request, decision)
            if inspect.isawaitable(lease):
                lease = await lease
            if lease is not None:
                self.policy.leases.add(lease)
                decision = self.policy.decide(
                    manifest, authority, prepared.request, prepared.facts)
        if not decision.allowed:
            if prepared.abort is not None:
                abandoned = prepared.abort()
                if inspect.isawaitable(abandoned):
                    await abandoned
            return {
                "denied": True,
                "error": decision.reason,
                "effect": decision.effect.value if decision.effect else None,
            }
        # Reads conservatively taint every later request in this invocation.
        # Persistent-worker state adapters must additionally persist the same
        # labels with any stored value.
        if decision.observes:
            self._taint[invocation_id] = frozenset(
                (*current_taint, *decision.labels))
        value = prepared.enact()
        return await value if inspect.isawaitable(value) else value

    def finish_invocation(self, invocation_id: str) -> None:
        self._taint.pop(invocation_id, None)

    def invocation_taint(
        self,
        invocation_id: str,
        default: frozenset[DataLabel] = frozenset({DataLabel.PUBLIC}),
    ) -> frozenset[DataLabel]:
        """Return the current joined label without transferring ownership."""
        return self._taint.get(invocation_id, default)


class LocalCapabilityTransport:
    """SDK transport for tests and explicitly promoted TCB plugins.

    It still crosses the broker for semantic parity and audit, but in-process
    code is already fully trusted and could bypass it; this class does not claim
    otherwise.
    """

    def __init__(self, broker: CapabilityBroker, *, invocation_id: str,
                 manifest: PluginManifest, authority: AuthorityContext):
        self.broker = broker
        self.invocation_id = invocation_id
        self.manifest = manifest
        self.authority = authority

    async def request(self, right: str, payload: Mapping[str, Any]) -> Any:
        return await self.broker.fulfill(
            invocation_id=self.invocation_id,
            manifest=self.manifest,
            authority=self.authority,
            right=right,
            payload=payload,
        )

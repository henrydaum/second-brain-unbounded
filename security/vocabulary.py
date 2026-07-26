"""Closed, kernel-versioned capability descriptors."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EffectKind(str, Enum):
    OBSERVE = "observe"
    MUTATE = "mutate"
    EGRESS = "egress"
    ADMINISTER = "administer"


@dataclass(frozen=True)
class CapabilityDescriptor:
    right: str
    # ``effect`` is display/audit shorthand only.  Authorization uses the
    # independent dimensions below; a request may both observe and egress.
    effect: EffectKind
    observes: bool = False
    mutates: bool = False
    egresses: bool = False
    administers: bool = False
    resource_required: bool = False
    may_be_reversible: bool = False
    autonomous: bool = False


def _d(right: str, effect: EffectKind, *, reversible: bool = False,
       autonomous: bool = False, observes: bool | None = None,
       resource_required: bool | None = None) -> CapabilityDescriptor:
    is_observe = effect == EffectKind.OBSERVE if observes is None else observes
    is_mutate = effect == EffectKind.MUTATE
    return CapabilityDescriptor(
        right=right,
        effect=effect,
        observes=is_observe,
        mutates=is_mutate,
        egresses=effect == EffectKind.EGRESS,
        administers=effect == EffectKind.ADMINISTER,
        resource_required=(
            (is_observe or is_mutate)
            if resource_required is None else resource_required),
        may_be_reversible=reversible,
        autonomous=autonomous,
    )


CAPABILITIES: dict[str, CapabilityDescriptor] = {
    "files.read": _d("files.read", EffectKind.OBSERVE),
    "files.list": _d("files.list", EffectKind.OBSERVE),
    "files.stat": _d("files.stat", EffectKind.OBSERVE),
    "files.write": _d("files.write", EffectKind.MUTATE, reversible=True),
    "files.delete": _d("files.delete", EffectKind.MUTATE, reversible=True),
    "files.move": _d("files.move", EffectKind.MUTATE, reversible=True),
    "data.read": _d("data.read", EffectKind.OBSERVE),
    "data.write": _d("data.write", EffectKind.MUTATE, reversible=True),
    "data.admin_sql": _d("data.admin_sql", EffectKind.ADMINISTER),
    "network.http": _d(
        "network.http", EffectKind.EGRESS, observes=True,
        resource_required=False),
    "network.websocket": _d(
        "network.websocket", EffectKind.EGRESS, observes=True,
        resource_required=False),
    "network.listen": _d(
        "network.listen", EffectKind.EGRESS, autonomous=True, observes=True,
        resource_required=False),
    "models.complete": _d(
        "models.complete", EffectKind.EGRESS, observes=True,
        resource_required=False),
    "models.embed": _d(
        "models.embed", EffectKind.EGRESS, observes=True,
        resource_required=False),
    "runtime.ask_user": _d(
        "runtime.ask_user", EffectKind.OBSERVE, resource_required=False),
    "runtime.call_tool": _d("runtime.call_tool", EffectKind.MUTATE),
    "runtime.schedule": _d(
        "runtime.schedule", EffectKind.MUTATE, reversible=True, autonomous=True),
    "runtime.emit": _d("runtime.emit", EffectKind.MUTATE),
    "runtime.notify": _d(
        "runtime.notify", EffectKind.EGRESS, resource_required=False),
    "runtime.conversation_read": _d(
        "runtime.conversation_read", EffectKind.OBSERVE),
    "runtime.conversation_write": _d(
        "runtime.conversation_write", EffectKind.MUTATE, reversible=True),
    "runtime.spawn_agent": _d(
        "runtime.spawn_agent", EffectKind.MUTATE, autonomous=True),
    "runtime.package_admin": _d(
        "runtime.package_admin", EffectKind.ADMINISTER),
    "process.run": _d(
        "process.run", EffectKind.EGRESS, observes=True,
        resource_required=False),
    "process.host_run": _d("process.host_run", EffectKind.ADMINISTER),
    "outputs.respond": _d("outputs.respond", EffectKind.OBSERVE),
    "outputs.attach": _d("outputs.attach", EffectKind.OBSERVE),
}


def descriptor(right: str) -> CapabilityDescriptor | None:
    return CAPABILITIES.get(right)

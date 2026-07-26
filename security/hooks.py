"""Typed, serializable extension points around kernel-owned conversation flow."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from plugins.proxy import PluginProxy

HOOK_MOMENTS = frozenset({
    "turn_start", "shape_scope", "vet_permission", "model_request",
    "model_response", "end_turn", "turn_finish",
})


class HookAction(str, Enum):
    ABSTAIN = "abstain"
    TRANSFORM = "transform"
    VETO = "veto"
    REDRIVE = "redrive"
    RECOMMEND_APPROVAL = "recommend_approval"


@dataclass(frozen=True)
class HookResult:
    action: HookAction = HookAction.ABSTAIN
    patch: Mapping[str, Any] = field(default_factory=dict)
    reason: str = ""

    @classmethod
    def from_wire(cls, raw: Any) -> "HookResult":
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            raise ValueError("hook result must be an object")
        unknown = set(raw) - {"action", "patch", "reason"}
        if unknown:
            raise ValueError(f"unknown hook result fields: {sorted(unknown)}")
        try:
            action = HookAction(raw.get("action", "abstain"))
        except ValueError as exc:
            raise ValueError("unknown hook action") from exc
        patch = raw.get("patch") or {}
        if not isinstance(patch, dict):
            raise ValueError("hook patch must be an object")
        _assert_json_value(patch)
        reason = raw.get("reason") or ""
        if not isinstance(reason, str):
            raise ValueError("hook reason must be text")
        return cls(action, patch, reason)


class TypedHookRegistry:
    """Deterministic proxy registry with fail-safe semantics."""

    def __init__(self):
        self._hooks: dict[str, list[PluginProxy]] = {
            moment: [] for moment in HOOK_MOMENTS}

    def add(self, moment: str, proxy: PluginProxy) -> None:
        if moment not in HOOK_MOMENTS:
            raise ValueError(f"unknown hook moment {moment!r}")
        if proxy.family != "hook":
            raise ValueError("only hook proxies may be registered")
        self._hooks[moment].append(proxy)

    def remove_artifact(self, digest: str) -> None:
        for moment in self._hooks:
            self._hooks[moment] = [
                item for item in self._hooks[moment]
                if item.artifact_digest != digest]

    async def consult(self, moment: str, payload: Mapping[str, Any]) -> list[HookResult]:
        if moment not in HOOK_MOMENTS:
            raise ValueError(f"unknown hook moment {moment!r}")
        _assert_json_value(payload)
        results = []
        for proxy in tuple(self._hooks[moment]):
            try:
                raw = await proxy.invoke({
                    "moment": moment,
                    "payload": dict(payload),
                })
                result = HookResult.from_wire(raw)
            except Exception:
                # An extension failure never becomes an allow or a kernel-loop
                # failure.  The supervisor/audit layer records worker errors.
                result = HookResult()
            if moment == "vet_permission" and result.action == HookAction.TRANSFORM:
                # Permission hooks cannot synthesize an allow field through a
                # generic patch.  They may only veto, abstain, or recommend the
                # kernel's normal approval flow.
                result = HookResult()
            results.append(result)
            if result.action == HookAction.VETO:
                break
        return results


def _assert_json_value(value: Any) -> None:
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("hook payload must be strict JSON data") from exc


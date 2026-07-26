"""User-facing creation of narrowly scoped capability leases."""

from __future__ import annotations

import time

from security.capabilities import GrantLease

DENY = "Deny"
ONCE = "Allow once"
SESSION = "Allow this session"
HOUR = "Allow for one hour"
PERSIST = "Allow until revoked"
CHOICES = [DENY, ONCE, SESSION, HOUR, PERSIST]


class RuntimeLeaseApprover:
    def __init__(self, runtime, *, timeout: float = 300.0):
        self.runtime = runtime
        self.timeout = float(timeout)

    def __call__(self, manifest, authority, request, decision):
        # Unattended work cannot summon a human.  A pre-existing lease must
        # explicitly allow unattended use.
        if authority.unattended or not authority.session_key:
            return None
        if not self.runtime.is_attended(authority.session_key):
            return None
        labels = ", ".join(
            item.name.lower().replace("_", "-")
            for item in sorted(decision.labels)) or "public"
        provenance = " -> ".join(
            f"{item.artifact_digest[:12]}:{item.handler}"
            for item in authority.provenance.frames)
        body = (
            f"Plugin: `{manifest.plugin_id}`\n\n"
            f"Artifact: `{authority.artifact_digest}`\n\n"
            f"Right: `{request.right}`\n\n"
            f"Resource: `{request.selector or '(none)'}`\n\n"
            f"Destination: `{request.destination or '(local)'}`\n\n"
            f"Data labels: `{labels}`\n\n"
            f"Call chain: `{provenance or '(root)'}`"
        )
        pending = self.runtime.request_input(
            authority.session_key,
            "Plugin capability request",
            body,
            type="string",
            enum=CHOICES,
            default=DENY,
        )
        if not pending.wait(self.timeout):
            pending.metadata["timed_out"] = True
            self.runtime.answer_request(
                authority.session_key, pending.id, DENY)
            return None
        if pending.metadata.get("cancelled") or pending.value == DENY:
            return None
        now = time.time()
        remaining = 1
        expires = None
        session_key = authority.session_key
        if pending.value == SESSION:
            remaining = None
        elif pending.value == HOUR:
            remaining = None
            expires = now + 3600
            session_key = None
        elif pending.value == PERSIST:
            remaining = None
            session_key = None
        elif pending.value != ONCE:
            return None
        return GrantLease.create(
            artifact_digest=authority.artifact_digest,
            principal=authority.principal,
            right=request.right,
            resource_selector=request.selector,
            destination=request.destination,
            allowed_labels=decision.labels,
            user_id=authority.user_id,
            session_key=session_key,
            conversation_id=authority.conversation_id,
            unattended=False,
            expires_at=expires,
            remaining_uses=remaining,
            provenance_digests=tuple(
                item.artifact_digest
                for item in authority.provenance.frames),
        )


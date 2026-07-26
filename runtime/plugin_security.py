"""Composition root for the clean-break plugin security runtime."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path

from paths import DATA_DIR, PLUGIN_ARTIFACTS, PLUGIN_TRUST_STORE
from plugins.manifest_discovery import discover_artifacts
from plugins.proxy import ProxyRegistry
from sandbox.backends import ProbeResult, SandboxUnavailable, current_backend
from sandbox.sdk_worker import SDKWorkerPool
from security.broker import CapabilityBroker
from security.capabilities import (
    AuthorityContext,
    PolicyEngine,
    ProvenanceChain,
    ResourceRegistry,
)
from security.file_adapter import FileCapabilityAdapter
from security.file_journal import DurableFileJournal
from security.data import DataCapabilityAdapter, PluginDataStore, TypedViewRegistry
from security.data import PluginDataBinding
from security.network import NetworkCapabilityAdapter
from security.outputs import AttachmentRegistry, OutputCapabilityAdapter
from security.secrets import SecretRegistry
from security.storage import CapabilityAuditLog, SqliteLeaseStore
from security.trust import TrustError, TrustStore
from security.trusted_runtime import TrustedArtifactRuntime

logger = logging.getLogger("PluginSecurity")


@dataclass
class PluginSecurityRuntime:
    resources: ResourceRegistry
    leases: SqliteLeaseStore
    secrets: SecretRegistry
    audit: CapabilityAuditLog
    policy: PolicyEngine
    broker: CapabilityBroker
    proxies: ProxyRegistry
    backend: object
    backend_probe: ProbeResult
    workers: SDKWorkerPool | None
    data_store: PluginDataStore
    views: TypedViewRegistry
    trust_store: TrustStore
    promoted_digests: frozenset[str]
    trusted_runtime: TrustedArtifactRuntime
    attachments: AttachmentRegistry
    artifact_roots: tuple[Path, ...] = (PLUGIN_ARTIFACTS,)
    discovery_errors: tuple[str, ...] = ()
    _runtime_views_bound: bool = False

    @property
    def isolated_plugins_available(self) -> bool:
        return bool(self.backend_probe.verified and self.workers is not None)

    async def activate_existing(self, roots=None):
        artifacts, errors = discover_artifacts(roots or self.artifact_roots)
        self.discovery_errors = tuple(errors)
        if errors:
            for error in errors:
                logger.error("Manifest plugin rejected: %s", error)
        if not artifacts:
            return ()
        activated = []
        for artifact in artifacts:
            try:
                if artifact.identity.digest in self.promoted_digests:
                    logger.warning(
                        "Loading digest-pinned TCB plugin in-process: %s (%s)",
                        artifact.identity.plugin_id,
                        artifact.identity.digest[:12],
                    )
                    invoker = await self.trusted_runtime.invoker_for(artifact)
                elif self.isolated_plugins_available:
                    invoker = await self.workers.invoker_for(artifact)
                else:
                    logger.error(
                        "Manifest plugin %s remains disabled because the "
                        "sandbox is unavailable and it is not TCB-promoted: %s",
                        artifact.identity.plugin_id, self.backend_probe.reason)
                    continue
                staged = self.proxies.stage(artifact, invoker)
                self.proxies.activate(staged)
                activated.extend(staged)
            except Exception:
                logger.exception(
                    "Manifest plugin failed activation: %s", artifact.root)
        return tuple(activated)

    def close(self):
        if self.workers is not None:
            self.workers.close()

    def bind_runtime(self, runtime) -> None:
        from runtime.capability_approvals import RuntimeLeaseApprover
        self.broker.approval_provider = RuntimeLeaseApprover(runtime)
        if self._runtime_views_bound:
            return

        def require_user(authority):
            if authority.user_id is None:
                raise PermissionError(
                    "the invocation has no kernel-bound user identity")
            return authority.user_id

        def require_current_conversation(authority):
            if not authority.session_key or authority.conversation_id is None:
                raise PermissionError(
                    "the invocation has no current conversation")
            conversation_id = int(authority.conversation_id)
            if not runtime.assert_conversation_access(
                    authority.session_key, conversation_id):
                raise PermissionError("conversation is not owned by this session")
            return conversation_id

        def current_conversation(authority, _params):
            conversation_id = require_current_conversation(authority)
            row = runtime.db.get_conversation(conversation_id)
            if row is None:
                raise PermissionError("current conversation no longer exists")
            return row

        def current_messages(authority, params):
            conversation_id = require_current_conversation(authority)
            limit = _bounded_limit(params.get("limit", 200), maximum=2000)
            rows = runtime.db.get_conversation_messages(conversation_id)
            return rows[-limit:]

        def conversations(authority, params):
            user_id = require_user(authority)
            limit = _bounded_limit(params.get("limit", 50), maximum=200)
            return runtime.db.list_conversations(limit=limit, user_id=user_id)

        self.views.register("conversation.current", current_conversation)
        self.views.register("conversation.messages", current_messages)
        self.views.register("conversations.list", conversations)
        self._runtime_views_bound = True

    def issue_plugin_data(
        self,
        *,
        artifact_digest: str,
        principal: str,
        namespace: str,
        selector: str = "state",
        alias: str = "state",
        rights=("data.read", "data.write"),
        allowed_views=(),
        user_id: int | None = None,
        session_key: str | None = None,
        conversation_id: int | None = None,
        expires_at: float | None = None,
        delegation_depth: int = 0,
    ):
        """Issue a kernel-owned data handle; never callable by plugin code."""
        return self.resources.issue(
            artifact_digest=artifact_digest,
            principal=principal,
            rights=rights,
            selector=selector,
            alias=alias,
            user_id=user_id,
            session_key=session_key,
            conversation_id=conversation_id,
            expires_at=expires_at,
            delegation_depth=delegation_depth,
            binding=PluginDataBinding(
                namespace=namespace,
                allowed_views=frozenset(allowed_views),
            ),
        )


def _bounded_limit(value, *, maximum: int) -> int:
    if isinstance(value, bool):
        raise ValueError("limit must be an integer")
    try:
        value = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer") from exc
    if value < 1:
        raise ValueError("limit must be positive")
    return min(value, maximum)


def build_plugin_security(db, *,
                          artifact_root: str | Path = PLUGIN_ARTIFACTS,
                          helper: str | Path | None = None,
                          trust_store_path: str | Path = PLUGIN_TRUST_STORE,
                          ) -> PluginSecurityRuntime:
    resources = ResourceRegistry()
    leases = SqliteLeaseStore(db)
    secrets = SecretRegistry()
    audit = CapabilityAuditLog(db)
    policy = PolicyEngine(resources, leases, audit=audit.record)
    broker = CapabilityBroker(policy)
    proxies = ProxyRegistry()
    trust_store = TrustStore(trust_store_path)
    try:
        promoted_digests = frozenset(
            record.digest for record in trust_store.records())
    except TrustError as exc:
        logger.error("TCB trust store rejected; no promotions loaded: %s", exc)
        promoted_digests = frozenset()
    trusted_runtime = TrustedArtifactRuntime(broker)

    journal = DurableFileJournal(DATA_DIR / "capability_journal" / "files")
    journal.recover_incomplete()
    files = FileCapabilityAdapter(resources, journal)
    broker.register("files.read", files.prepare_read)
    broker.register("files.list", files.prepare_list)
    broker.register("files.stat", files.prepare_stat)
    broker.register("files.write", files.prepare_write)
    broker.register("files.delete", files.prepare_delete)
    broker.register("files.move", files.prepare_move)
    network = NetworkCapabilityAdapter(secret_resolver=secrets.resolve)
    broker.register("network.http", network.prepare_http)
    attachments = AttachmentRegistry(
        DATA_DIR / "capability_attachments")
    outputs = OutputCapabilityAdapter(resources, attachments)
    broker.register("outputs.attach", outputs.prepare_attach)
    data_store = PluginDataStore(db)
    data = DataCapabilityAdapter(resources, data_store, TypedViewRegistry())
    broker.register("data.read", data.prepare_read)
    broker.register("data.write", data.prepare_write)

    try:
        backend = current_backend(helper)
        probe = backend.probe()
    except SandboxUnavailable as exc:
        backend = None
        probe = ProbeResult(False, False, "none", str(exc))

    workers = None
    if probe.verified:
        def authority_factory(artifact, handler):
            digest = artifact.identity.digest
            return AuthorityContext(
                artifact_digest=digest,
                principal="agent",
                provenance=ProvenanceChain("agent").enter(
                    digest, f"{handler.kind}:{handler.name}"),
            )

        workers = SDKWorkerPool(
            backend, broker, authority_factory,
            DATA_DIR / "plugin_workers")
    else:
        logger.warning(
            "Isolated manifest plugins are fail-closed: %s: %s",
            probe.backend, probe.reason)
    return PluginSecurityRuntime(
        resources=resources,
        leases=leases,
        secrets=secrets,
        audit=audit,
        policy=policy,
        broker=broker,
        proxies=proxies,
        backend=backend,
        backend_probe=probe,
        workers=workers,
        data_store=data_store,
        views=data.views,
        trust_store=trust_store,
        promoted_digests=promoted_digests,
        trusted_runtime=trusted_runtime,
        attachments=attachments,
        artifact_roots=(Path(artifact_root),),
    )


def start_plugin_security(db, **kwargs) -> PluginSecurityRuntime:
    runtime = build_plugin_security(db, **kwargs)
    asyncio.run(runtime.activate_existing())
    return runtime

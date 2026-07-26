"""Kernel-owned capability-security primitives.

This package must not import plugin implementations.  It is part of the trusted
computing base and deliberately contains only data parsing, identity, policy,
artifact verification, and durable decision support.
"""

from security.artifacts import ArtifactId, PluginArtifact, build_artifact
from security.capabilities import (
    AuthorityContext,
    CapabilityRequest,
    DataLabel,
    EffectKind,
    GrantLease,
    LeaseStore,
    MediationFacts,
    PolicyDecision,
    PolicyEngine,
    ProvenanceChain,
    ResourceRef,
    ResourceRegistry,
)
from security.manifest import PluginManifest, load_manifest
from security.storage import CapabilityAuditLog, SqliteLeaseStore

__all__ = [
    "ArtifactId",
    "AuthorityContext",
    "CapabilityRequest",
    "CapabilityAuditLog",
    "DataLabel",
    "EffectKind",
    "GrantLease",
    "LeaseStore",
    "MediationFacts",
    "PluginArtifact",
    "PluginManifest",
    "PolicyDecision",
    "PolicyEngine",
    "ProvenanceChain",
    "ResourceRef",
    "ResourceRegistry",
    "SqliteLeaseStore",
    "build_artifact",
    "load_manifest",
]

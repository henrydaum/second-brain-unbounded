# Trust and placement

This document separates three questions that the old plugin runtime conflated:

1. What may an artifact request?
2. What resources and grant leases does this invocation hold?
3. Where is the artifact allowed to execute?

The first two are capability policy.  The third is placement and containment.

## Python is not the boundary

Python source inspection cannot prove that arbitrary code is safe.  Module
objects, reflection, C extensions, third-party dependencies, and future runtime
changes make the reachable object graph impossible to secure with an import
allowlist.  `python -I`, stripped builtins, AST checks, and import checks remain
useful diagnostics and defense-in-depth; they are not a security sandbox.

The legacy generator runner under `sandbox/` is retained as a migration test
oracle.  Production executable discovery of DATA_DIR Python files fails closed
unless the test-only `SECOND_BRAIN_ENABLE_LEGACY_PLUGIN_ORACLE=1` switch is set.

## Isolated placement

Every separately installed or agent-authored extension is isolated by default,
including store packages and all of their dependencies.  An isolated worker:

- is launched by a verified OS backend;
- sees its immutable artifact, SDK runtime, private scratch directory, and one
  protocol channel;
- has no ambient host filesystem, network, process, credential, database, GUI,
  clipboard, registry, model, session, or kernel-object authority;
- uses a strict length-prefixed JSON protocol;
- receives only opaque resource and secret references;
- is constrained by CPU, memory, process, output, and wall-time budgets.

The backend must pass hostile probes for filesystem, network, process, IPC, and
inherited-handle denial.  If it cannot, isolated plugins do not run.  There is
no Python-only fallback.

The backend adapters and policy are in `sandbox/backends.py`; native helpers are
platform deliverables.  A helper is not considered verified merely because it
exists: it must report the matching policy version and pass every required
probe.

## Artifact identity

New extensions are directories containing `plugin.toml` and `plugin.lock`.
Discovery parses both as data and never imports extension code.  The lock names
each resolved dependency archive and its SHA-256; unlisted wheel files are
rejected. `security.artifacts` hashes every regular file in canonical
relative-path order, including bytecode, the manifest, and dependency lock.
Symlinks and special files are refused.

Trust, resources, leases, workers, and proxies bind to that complete digest.
Editing any byte creates a new principal; grants never transfer automatically.
Store signatures authenticate who published bytes but do not make those bytes
safe.

## Explicit TCB promotion

Performance-sensitive code may be promoted into the trusted computing base only
through a local developer operation.  Promotion:

- pins the complete artifact digest;
- requires the exact full-compromise acknowledgement;
- records who approved it and when;
- takes effect after restart;
- is not represented in the plugin capability vocabulary and therefore cannot
  be called by a plugin or agent.

An in-process plugin and every dependency it can reach have the authority of
Second Brain itself.  The SDK still routes normal operations through the broker
for compatibility and audit, but this is voluntary once code is inside the TCB.
Trusted placement is not a more permissive capability lease; it is an explicit
decision to abandon containment for those exact bytes.

## Authority is independent of placement

A manifest declaration is only a maximum request shape.  It does not grant
resources or authorize an operation.  The reference monitor intersects:

- kernel-derived principal and ownership;
- complete caller provenance;
- artifact declaration;
- opaque resource authority;
- information labels and destination;
- active scoped grant lease;
- platform and kernel policy.

Delegation can only narrow rights, selector, expiry, usage, and delegation
depth.  Hooks can veto or request policy, but cannot manufacture an allow.
Credentials remain kernel-owned and are inserted only at a destination-bound
network/model sink.

See [SECURITY_ARCHITECTURE.md](../docs/SECURITY_ARCHITECTURE.md) for the
executable invariants and [CAPABILITY_PARITY.md](../docs/CAPABILITY_PARITY.md)
for migration status.

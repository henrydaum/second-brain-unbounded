# Capability-security architecture

## Security claim

An isolated plugin may compute arbitrarily, but it cannot observe or change a
host resource except through a kernel-issued capability.  The kernel authorizes
each request using kernel-derived identity, the complete caller provenance
chain, the plugin artifact digest, an opaque resource reference, information
labels, the destination, and any applicable grant lease.

This claim assumes that the kernel, reference monitor, selected operating-system
sandbox backend, and operating system are trusted.  Denial of service, covert
timing channels, and a compromised local account or operating system are not
eliminated.

## Non-negotiable invariants

1. Plugin discovery parses data.  It never imports, instantiates, or reflects on
   extension code.
2. An extension artifact is identified by a digest of every shipped file,
   including its manifest and dependency lock.  A changed byte creates a
   different authority principal.
3. An untrusted worker starts without ambient filesystem, network, process,
   credential, database, registry, session, or model authority.
4. The only useful worker-to-host channel is the versioned capability protocol.
   Protocol input is length bounded and schema checked; Python objects and
   pickle never cross it.
5. A declaration is only a ceiling.  It never grants a resource or authorizes a
   sensitive operation.
6. Principals, ownership, provenance, attendance, and reversibility are derived
   by the kernel.  A plugin cannot assert any of them.
7. Delegation only attenuates: rights, selectors, expiry, usage count, labels,
   and delegation depth can stay equal or become narrower, never broader.
8. Trust and grant leases bind to the complete artifact digest.  They do not
   transfer to an update.
9. A mutation is called reversible only after the kernel has durably recorded
   an inverse before making the mutation externally visible.
10. Every egress sink checks the joined information labels accumulated by the
    invocation and persistent plugin state.
11. Hooks may observe, transform serializable data, veto, or request kernel
    actions.  They cannot receive live kernel objects or override a denial.
12. If a verified OS backend is unavailable or fails its hostile self-test,
    isolated plugins do not run.  Python import and AST restrictions are
    defense-in-depth, not a sandbox.
13. TCB promotion is a local developer operation, pins the complete digest,
    requires an explicit full-compromise acknowledgement, and takes effect only
    after restart.  It is not callable through the plugin capability protocol.

These rules implement complete mediation, least authority, fail-safe defaults,
and confused-deputy resistance.  Rice's theorem is the reason there is no rule
that attempts to infer authority from what source code appears to do.

## Policy dimensions

The old `read < write < egress` ordering remains useful as display shorthand,
but is not an authorization model.  The reference monitor evaluates:

- requested right and resource selector;
- confidentiality label of every value available to the invocation;
- integrity impact and whether atomic undo is established;
- local, external, administrative, and autonomous effects;
- destination and credential reference;
- user, session, conversation, attendance, and provenance;
- manifest ceiling, resource authority, and scoped grant lease.

A public read through an already-held resource reference needs no repeated
prompt.  A reversible write through an already-held resource reference needs no
repeated prompt after its inverse is established.  Sensitive reads, external
sinks, irreversible mutations, administration, and unattended autonomy require
matching leases.

## Legacy boundary

The generator/effects runner and executable plugin discoverer are migration
oracles only.  They are not verified hostile-code containment.  New extension
packages use `plugin.toml`, immutable artifacts, `PluginProxy`, the async SDK,
and an OS-confined worker.  There is no production fallback from that path to
the legacy loader.


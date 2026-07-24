# The Primitive Constitution

This document is the admission policy for `effects/vocabulary.py` — the closed
vocabulary of requests a sandboxed tool may yield. It exists because the whole
safety model stands or falls on this set staying **small, general, and closed**.

## Why a definitive list is possible

Rice's theorem forbids judging arbitrary *programs*: the set of programs is
unbounded and their properties undecidable. But the set of *resources* is
finite. A sandboxed process with no ambient authority can only touch what the
boundary explicitly offers — the OS itself is the existence proof (a finite
syscall table, from which every program ever written is composed). So we do not
enumerate what plugins might want to do (unbounded); we enumerate what the
platform has (finite): conversation, filesystem, database, environment, the
user, the network, the LLM. The primitive list is a projection of that resource
inventory, and every safety property lives on this boundary, decided at
runtime, decidably.

## Why exactly three tiers

Classify any effect by two questions: *does state change?* and *does
information cross the trust boundary* (leave the machine / reach a party we
don't control)? The 2×2 collapses to three because crossing dominates:

|                     | no crossing | crossing |
|---------------------|-------------|----------|
| **no state change** | `read`      | `egress` (a GET) |
| **state change**    | `write`     | `egress` (a POST) |

- **`read`** — information flows *in* from confined local state. Safe for
  every tool, alone. Its only risk is in combination with egress — which tier
  derivation surfaces automatically (`read` + `egress` declarations ⇒ an
  egress-tier tool; the gate sees the whole request stream).
- **`write`** — local mutation, safe **iff the kernel can journal it**.
  Reversibility is by construction (the `TurnJournal`), never by trust. An
  effect the kernel *cannot* journal is not a write — it is egress-equivalent
  (irreversibility is the property, not the network): printing a page, playing
  a sound, deleting without a recoverable copy.
- **`egress`** — irreversible in principle: you cannot unsend. Verb is
  irrelevant; a GET's URL is a payload. Always gated.

These labels are **structural, not judgment calls** — no per-plugin reasoning
appears anywhere. That is the entire Rice dodge.

## The generality bar (the admission test)

A primitive earns its place by being the shared floor many tools stand on.
Apply, in order:

1. **Resource, not algorithm.** If the candidate is expressible as pure code
   over existing primitives, it is a tool (or a shared pure kit function), not
   a primitive. *The grep lesson:* `Grep`/`Glob` were briefly kernel requests —
   algorithms wearing resource badges. They were decomposed into
   `ListDir` + `ReadFiles` + pure matching in the tool. Verbs creep;
   resources don't.
2. **General purpose.** Would tools from *different* families call it? A
   primitive that exists for one plugin is that plugin's algorithm in
   disguise. (One legitimate exception pattern: a new egress *transport* —
   email, MCP — is inherently specific but still admitted, because raw
   sockets are never handed out; each transport is one mediated verb.)
3. **Which domain?** Almost every candidate is a new *mode* on an existing
   domain. A genuinely new domain should be roughly never.
4. **Tier by structure.** Journalable? → write. Anything crossing to an
   uncontrolled party (or irreversible)? → egress. Neither? → read.
5. **Batching is not semantics.** A batched variant (`ReadFiles`) exists for
   round-trip economy and inherits its element's tier.

## The domain inventory (v1)

| Domain | Primitives | Tier |
|---|---|---|
| Conversation | `ReadContext(view)` · `Respond` (terminal) | read (implicit — never declared) |
| Filesystem | `ListDir` · `Stat` · `ReadFile` · `ReadFiles` | read |
| | `WriteFile` (journaled, root-confined) | write |
| Database | `QueryDb` (SELECT/PRAGMA-guarded) | read |
| | `WriteDb` (own output tables, journaled) | write |
| Network / services | `HttpRequest` · `Complete` (LLM served kernel-side; keys never enter the sandbox) | egress |
| Compute | none — CPU/memory/time are sandbox budgets, not requests; process-spawning is not offered | — |
| Kernel state | none in v1 — config holds API keys; a read there composes with egress into key theft | — |
| User | none yet — a future `AskUser` is *not* egress (the human is inside the trust domain) but gates on attendance | — |

## Standing rules

- **The deferred-execution rule.** A write that something later *executes* is
  not a write — it is escalation. Write roots must exclude everything the
  kernel interprets: plugin trees (`installed_plugins/`, `sandbox_plugins/`),
  config, the DB file as a raw path. A write aimed there is refused or
  reclassified as gated. This is the classic capability-security failure mode;
  it also keeps journal *rollback* safe in both directions.
- **Nondeterminism enters through the boundary.** Time, randomness, and LLM
  completions must be requests (or params), never ambient — this is what makes
  a tool run replayable, and it is exactly what will make conversation layers
  content-addressable later (a stored completion is the layer's "seed").
- **Covert channels are out of scope.** Timing and resource-exhaustion
  channels exist in every practical sandbox; they are low-bandwidth and
  accepted, not denied.
- **Confinement is context, not vocabulary.** Read/write roots, user scoping,
  and the egress gate live in `EffectContext` — policy per run, not new
  request types.

Prior art this deliberately follows: object-capability security (no ambient
authority), WASI (capability-scoped, resource-oriented syscalls), Capsicum.
The egress-dominates rule is taint-sink analysis done dynamically at one
chokepoint instead of statically over all code.

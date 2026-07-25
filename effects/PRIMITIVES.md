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

**And the dodge only works because we never ask the semantic question.** Whether
a given string leaving the machine is benign or hostile is undecidable in
practice — Rice's theorem wearing a natural-language costume — so the system
never tries. What *is* decidable, cheaply and totally, is the shape of the
operation: does it change state, and can the change be undone? Every control in
this document reduces to those two questions. Anything that would require
reading meaning out of content is out of scope by construction, not by omission.

The corollary is worth stating because it bounds what the compositional check
below can claim: tracking that a run *read local data before transmitting* is
structural and therefore fair game, but it says nothing about whether what left
was sensitive. It is a fact about operations, offered to a human, not a verdict.

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

## The domain inventory

| Domain | Primitives | Tier |
|---|---|---|
| Conversation | `ReadContext(view)` · `Respond` (terminal) | read (implicit — never declared) |
| Filesystem | `ListDir` · `Stat` · `ReadFile` · `ReadFiles` | read |
| | `WriteFile` · `DeleteFile` (journaled — the kernel snapshots prior bytes; root-confined) | write |
| Database | `QueryDb` (SELECT/PRAGMA-guarded) | read |
| | `WriteDb` (own output tables, journaled) | write |
| | `ExecSql` (arbitrary mutation — **not** journalable, so egress-graded and gated) | egress |
| Network / services | `HttpRequest` · `Complete` · `Embed` (LLM/embedder served kernel-side; keys never enter the sandbox) | egress |
| Compute / process | `RunProcess` (argv only — no shell string; cwd-confined; kernel owns the handle) | egress |
| Kernel state | none — config holds API keys; a read there composes with egress into key theft | — |
| User | `AskUser` — *not* egress (the human is inside the trust domain, so requiring approval to request approval would be circular); gates on **attendance**, a liveness check, so an unattended session fails fast instead of hanging on a prompt nobody will see. The answer is untrusted text, like file contents. | read |

**`ReadContext` ambient views.** Beyond conversation text, `ReadContext` resolves
a few non-secret *facts* about the run straight off `EffectContext`:
`conversation_id`, `user_id`, `paths` (resolved locations — root, data, scratch,
memory root — never config values or keys). These are read-tier and available to
even a `params_only` tool: knowing *where you are* and *whose data this is* is not
conversation content, and paths are not secrets. This is a mode on an existing
read primitive, not a new domain.

**Why process-spawning is now offered (amends the v1 "not offered" stance).** A
subprocess is irreversible and boundary-crossing, so it is not a write — it is
egress, and always gated. It is admitted under the same exception that admits
email and MCP transports (generality-bar #2): raw `fork`/`exec` is never handed
to a tool, only the single mediated `RunProcess` verb, with the kernel owning the
handle, confining the cwd, capping output, and routing every call through the
approval surface. CPU/memory/time remain sandbox *budgets*, not requests.

## Argument-level authorization

Tier answers *what kind of effect is this?* It cannot answer *is this particular
call entitled?* — that is a property of the arguments, decided at the point of
use, after normalization. `ReadFile("./notes.md")` and `ReadFile("~/.ssh/id_rsa")`
are one verb and two very different acts.

Three checks live in the interpreter, each guarding a domain:

- **Filesystem** — `_check_path` resolves (collapsing `..` and symlinks) and then
  compares *path components* via `Path.relative_to`, never string prefixes, so a
  grant over `src` never admits `src2`. Never weaken this to a prefix test.
- **Egress URLs** — `_check_egress_url` admits only `http`/`https`. This is not
  redundant with the egress gate: `file://` is a **local read wearing an egress
  badge**, and urllib serves it happily, bypassing `read_roots` entirely. Also
  refused: credentials in the URL (they would land in ledger rows and the
  approval dialog) and link-local/metadata hosts (169.254.169.254 is an
  unauthenticated credential source). Broader private-network access stays
  allowed-but-gated — a human sees the target, and local services are legitimate.
- **SQL identifiers** — `_check_sql_tables` refuses any statement naming a denied
  table (`DENIED_SQL_IDENTIFIERS`, currently `users`). Read tier does not mean
  every row is fair game: `users` holds `password_hash` and the per-user config
  blob, `QueryDb` is *ungated* read tier, and `Complete`/`Embed` are allowed by
  default — so the pair composes directly into credential exfiltration. This is
  the kernel-state hazard in the domain table made executable. Identity is
  available the safe way through `ReadContext("user_id")`.

Confinement remains context, not vocabulary: these are policies on
`EffectContext`, not new request types.

## Standing rules

- **The deferred-execution rule.** A write that something later *executes* is
  not a write — it is escalation. Write roots must exclude everything the
  kernel interprets: plugin trees (`installed_plugins/`, `sandbox_plugins/`),
  config, the DB file as a raw path. A write aimed there is refused or
  reclassified as gated. This is the classic capability-security failure mode;
  it also keeps journal *rollback* safe in both directions.

  **Concretely:** `discover_tools` instantiates every `BaseTool` subclass under
  the sandbox plugin root and runs it **in-process with the live context**. So an
  approval-free write into that tree is a complete escape — a sandboxed tool
  authors a plain (non-sandboxed) plugin and has full authority on the next load.
  The tree therefore stays inside `write_roots` (authoring still works) but is
  **not** in `free_write_roots` (it costs one approval). Pinned by
  `tests/test_effect_authorization.py::test_plugin_tree_is_not_a_free_write_root`.
  Once the trust model below lands, provenance contains such a plugin
  automatically — but the approval stays, because two independent controls on the
  one path that converts data into code is the right number.
- **Nondeterminism enters through the boundary — for the effects that matter.**
  LLM completions and embeddings are requests, never ambient: they are egress,
  they cost money, and a stored completion is the seed a content-addressed turn
  would hash. Time and randomness are deliberately **left ambient** (`time`,
  `random`, `uuid` stay importable). They are not security-relevant — a clock
  read crosses no boundary and mutates nothing — and routing them through the
  wire would buy only replayability, which nothing consumes yet. If the
  conversation-DAG work later needs deterministic replay, the fix is to add
  `Now`/`Random` requests and drop those modules from the import allowlist; until
  then the cost is not worth paying. Recorded here so the gap is a decision
  rather than an oversight.
- **Covert channels are out of scope.** Timing and resource-exhaustion
  channels exist in every practical sandbox; they are low-bandwidth and
  accepted, not denied.
- **Confinement is context, not vocabulary.** Read/write roots, user scoping,
  and the egress gate live in `EffectContext` — policy per run, not new
  request types.

## Trust: two execution modes, one contract

Every plugin declares its requests and runs its body as a generator over this
vocabulary. **Where** that body runs is a separate axis:

- **untrusted** — a subprocess (`sandbox/`). Isolation by construction.
- **trusted** — in-process. No subprocess, no AST gate.

**Trusted mode is not a bypass.** Both modes drive the same generator
(`sandbox/driver.py`) through the same `Interpreter`, so tiers, argument-level
checks, journalling, the egress gate, and ledger rows are identical. The mode
selects only whether a process boundary exists — pinned by
`tests/test_execution_modes.py`, which asserts the same plugin produces the same
result *and the same ledger rows* both ways.

Measured: a request crossing the pipe costs 0.013 ms and a resident child ~4 MB,
but a cold untrusted call costs **~520 ms** against **~4.6 ms** trusted — and that
gap is startup, dominated by the child's imports rather than by spawn. So the
modes buy speed as well as debuggability, and a warm worker pool is a
requirement rather than an optimization.

Two consequences that must not erode:

- **Trust is a flag, never a rewrite.** One contract per family — there is no
  parallel `BaseSandbox<Family>` hierarchy. If switching modes required editing a
  plugin, demotion would be expensive enough that it would never happen, and the
  whole model would decay into "everything is trusted".
- **Trusted mode does not hand out live objects.** A trusted plugin still yields
  `QueryDb`; it does not receive `context.db`. The moment live objects are handed
  over as a convenience, trust becomes a rewrite again. Wanting live objects is
  exactly what defines the exemption list below.

**Trust is provenance, not origin.** Built-in kernel plugins are trusted.
Everything else — including everything installed from the store — is untrusted
unless its SHA-256 is recorded as reviewed. Trust binds to *reviewed bytes*, so
any edit silently drops a plugin back to untrusted, and "it came from the
registry" is never evidence of anything.

## What requires the always-trusted exception

The goal is that a plugin's security level is **not** a per-plugin judgement.
Almost everything is sandboxable, and the few exceptions should be nameable in
one page — otherwise "is this safe?" becomes a case-by-case argument, which is
exactly what this design exists to avoid.

So the exception is defined by **capability, not by plugin**. A plugin needs the
always-trusted exception if, and only if, it needs one of these five things.
Everything else is sandboxable, whatever family it belongs to.

| # | Capability | Why it cannot cross | Examples |
|---|---|---|---|
| 1 | **Hold a live handle across calls** — a socket, file descriptor, database cursor, GPU context | The handle *is* the authority. Serialising it either fails or copies the authority, and a request-per-operation would be a different program. | `service_llm` (provider sockets, API keys) |
| 2 | **Own a thread or event loop** | Its work happens between calls, not during one; there is no body for the driver to drive. | `service_timekeeper`, frontend transports |
| 3 | **Mutate kernel registries** — register tools, load plugins, rebuild the task graph | Its whole purpose is changing what the kernel *is*. Mediating that would mean a request per registry mutation, i.e. re-implementing the kernel behind the wire. | `service_plugin_watcher`, `package_manager` |
| 4 | **Be called back synchronously by the kernel mid-operation** — streaming deltas, `proceed` escorts | A generator yields *outward*; it cannot also be re-entered inward from the kernel partway through. | `on_delta` streaming, `model_call` hook escorts |
| 5 | **Hand the kernel a live callable or object it will execute** — a validator, a hook function, a parser | The kernel would be running plugin code with the kernel's own authority, so the boundary never applies. | `parser_registry` (function registry), form `validator`s |

**What this costs the agent.** An agent-authored plugin cannot do any of the
five. Concretely, the agent cannot write: an LLM backend, a frontend transport,
a scheduler, a hot-reloader, a parser that registers a function, or anything that
streams. It *can* write tools, commands, tasks, ordinary services, and the
render/parse half of a frontend — which is nearly everything worth writing.

That is the trade, stated plainly: **the agent gets to write anything whose work
is expressible as "compute, then ask the kernel to act".** The five exceptions
are all cases where the plugin *is* infrastructure rather than a user of it.

**The current exception list** (every entry justified by a numbered capability
above — an entry that cannot cite one is a bug, not an exception):

| Component | Capability |
|---|---|
| `service_llm` + LLM backends | 1, 4 |
| `service_plugin_watcher` | 2, 3 |
| `service_timekeeper` | 2 |
| `parser_registry` / `service_parser` | 5 |
| frontend transports (`start`/`stop`, sockets) | 1, 2 |
| `package_manager` | 3 |

This list is closed, and growing it requires citing one of the five. A test
enumerates plugins still on the imperative contract and fails if it exceeds this
set, so the exception cannot expand quietly.

---

Prior art this deliberately follows: object-capability security (no ambient
authority), WASI (capability-scoped, resource-oriented syscalls), Capsicum.
The egress-dominates rule is taint-sink analysis done dynamically at one
chokepoint instead of statically over all code. The trust/authority split —
affordances may evolve, authority may not — follows Agent libOS (arXiv 2606.03895).

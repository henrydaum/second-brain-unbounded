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
   **Where a request's danger depends on what it triggers, derive it
   transitively rather than guessing.** Firing a bus channel is the worked
   example: emitting is not dangerous in itself, it is dangerous exactly in
   proportion to what listens, so the tier of an emit is the maximum derived
   tier of every task subscribed to it — following onward emits, and resolving
   cycles to the highest tier found (`runtime/service_ticker.channel_danger_tier`).
   A channel whose only subscriber reads files fires silently; one that reaches
   an HTTP call is gated. Nothing new is asserted anywhere: tasks already
   declare their requests, and their tiers already fall out of those
   declarations. This is the answer whenever a verb looks like "it depends" —
   it does depend, and the dependency is usually computable.
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
| Kernel registries | `ReloadPlugin` (load/reload/unload by path; root-confined — loading *executes code*, so the deferred-execution rule puts it here rather than in write) | egress |
| Kernel administration | `WriteConfig` · `ServiceControl` · `PackageOp` · `ConversationOp` — the kernel administers itself through slash commands, and those commands must reach config, services, packages and conversations to run as pure bodies. Irreversible or code-executing, hence egress; additionally graded by **who is asking** (below). | egress |
| Kernel state (reads) | none — config holds API keys; a read there composes with egress into key theft. Note `WriteConfig` must not become a read by returning the prior value. | — |
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
- **Tier is a property of the operation; entitlement can also depend on the
  asker.** Tier answers "how dangerous is this?" and never varies — a
  `WriteConfig` is egress whoever issues it. But for the **administration
  verbs**, the same operation is the user editing their own settings or an
  autonomous agent rewriting them, and those are not the same act. So a second
  axis grades them, in `effects/declarations.py::admin_disposition`:

  | | trusted plugin | untrusted plugin |
  |---|---|---|
  | **principal = user** | allow | approve |
  | **principal = agent** | approve | refuse |

  Two rules make this safe rather than a loophole:

  1. **Principal comes from the dispatch path, never the plugin's family.** A
     slash command is the user acting; a tool call in an agent turn is the agent
     acting. Inferring it from "this is a command" would make a command/tool
     bridge a straight escalation — the agent calls a tool that calls a command
     that saves config. A bridge must *propagate* its caller's principal.
  2. **Provenance is the second ceiling.** Otherwise the agent writes a command
     into `sandbox_plugins/` and waits for the user to run it, laundering agent
     authority into user authority. Requiring both axes closes that.

  Both default to the restrictive value, so a context that has not been taught
  about principals fails closed. `sandbox_trust_all` is deliberately *not* the
  trust input here: it answers "where does this body run?", not "whose code is
  it?" — conflating them would let a debug flag grant authority and would make
  the all-trusted equivalence run meaningless. Pinned by `tests/test_principal.py`.
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
Almost everything is sandboxable, and the exceptions should be nameable in one
page — otherwise "is this safe?" becomes a case-by-case argument, which is
exactly what this design exists to avoid.

So the exception is defined by **capability, not by plugin**. Crucially, this is
a list of **debt, not of laws**: only one entry is irreducible. The rest are
things we have not yet inverted, each with a known exit. An earlier version of
this section claimed all five were impossible; that was wrong, and the two
already retired are the proof.

| # | Capability | Status | Exit |
|---|---|---|---|
| 1 | **Hold a secret** — API keys, credentials | **irreducible** | none. See below. |
| 2 | **Own a thread or event loop** | **retired** | kernel-driven `tick` + `declared_channels` (`runtime/service_ticker.py`) |
| 3 | **Mutate kernel registries** — register tools, load plugins | **retired** | `ReloadPlugin` — egress tier (loading executes code, and import side effects cannot be un-run), root-confined and ledger-recorded. *More* mediated than the in-process version, which mutated registries with no audit trail at all. |
| 4 | **Be called back mid-operation** — streaming, `proceed` escorts | open | invert to yield/resume: an escort `yield`s `Proceed()` and reads the response as the resume value; streaming yields chunks outward. |
| 5 | **Hand the kernel a live callable** — a parser function, a validator | open | declare, don't hand over: a parser declares the extensions it handles as *data* and the kernel dispatches to it through the boundary. Blocked on parsers being helper modules rather than plugins, and on heavy parsers returning live PIL/numpy/`av` objects — which is really #1 in disguise, and whose own fix is to return a path instead of an object. |

Note what retiring #2 required, because it generalises: **the plugin stopped
owning the loop, and stopped touching the resource.** It is ticked rather than
looping, and it *returns* the events it wants fired rather than emitting them.
Both halves are the same move — never hand the plugin the live thing — and it is
the same move as a command returning a form spec instead of live `FormStep`s. #3,
#4 and #5 are all waiting on that same inversion, applied to registries,
callbacks and parsers.

### Why holding a secret is the one irreducible case

Every other capability is about *operations*, and operations are what this
boundary mediates. A secret is different: its entire value is confidentiality,
which is a property of **content**. And content is exactly what the design
refuses to judge — the Rice's-theorem dodge that makes everything else work is
also what blinds it here.

Concretely, once a key is a string in a plugin's memory, every channel the plugin
legitimately holds becomes an exfiltration path:

```python
yield Respond(summary=api_key)               # read tier, ungated
yield Complete(prompt=f"...{api_key}")       # to the model provider
yield WriteFile(path="notes.md", content=api_key)
```

None of those is a violation. The plugin is doing exactly what it declared. So
the rule is **use a capability without holding it**: the plugin asks for a
completion, the kernel attaches the key. What you never possess, you cannot leak.

This is narrow. It covers credentials only — which is why `service_llm` is the
sole permanent exception, and only its key-handling half.

**What this costs the agent**, today: it cannot write an LLM backend, a
hot-reloader, a parser that registers a function, or anything that streams. It
*can* write tools, commands, tasks, ordinary services (including periodic ones),
and the render half of a frontend. As #3–#5 are retired that list shrinks toward
credentials alone.

**The current exception list** (every entry cites a capability — an entry that
cannot is a bug, not an exception):

| Component | Capability |
|---|---|
| `service_llm` + LLM backends | 1, 4 |
| `service_plugin_watcher` | — *(retired: `ReloadPlugin` covers the mutation; still trusted only because it is built-in)* |
| `service_timekeeper` | — *(retired: kept trusted only because it is built-in, not because it must be)* |
| `parser_registry` / `service_parser` | 5 |
| frontend transports (`start`/`stop`, sockets) | 1, 2 |
| `package_manager` | 3 |

This list is closed, and growing it requires citing a capability. A test
enumerates plugins still on the imperative contract and fails if it exceeds this
set, so the exception cannot expand quietly — and the numbers above are what it
should shrink by.

---

Prior art this deliberately follows: object-capability security (no ambient
authority), WASI (capability-scoped, resource-oriented syscalls), Capsicum.
The egress-dominates rule is taint-sink analysis done dynamically at one
chokepoint instead of statically over all code. The trust/authority split —
affordances may evolve, authority may not — follows Agent libOS (arXiv 2606.03895).

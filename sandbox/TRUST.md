# Trust: who decides a plugin may use a library

This is the companion to [effects/PRIMITIVES.md](../effects/PRIMITIVES.md). That
document answers "what may a plugin *ask for*". This one answers "what may a
plugin *import*, and who says so".

---

## The problem, plainly

A plugin that only uses the Python standard library can be confined by reading
its code. We parse it, reject `open`/`eval`/`exec`/`__import__`, reject imports
outside a small allowlist, and run it in a subprocess with stripped builtins. The
only way out is the request pipe. That works.

A plugin that imports a third-party library cannot be confined that way, and the
reason is not that third-party libraries are untrustworthy. `croniter` is about
as innocent as software gets — pure date arithmetic, no I/O of its own. But
importing it hands the calling code this:

```
croniter.cron_m._traceback._colorize.os
```

Three attribute hops from the module object to `os`, by way of Python 3.14's
traceback colouriser. No banned name, no banned attribute, nothing suspicious
anywhere in croniter's source. From there, `os.system` does whatever it likes.

`cron_descriptor` is the same story through `gettext`. If those two fail, every
library fails. Python module objects are transitively reachable, the graph
changes on every upgrade, and C extensions are opaque to source analysis
entirely. There is no vetting process that fixes this, which is why no
application marketplace attempts one — Apple, Microsoft and Google all confine
the app at the OS level and use review for policy, not for safety.

So: **a plugin that imports a third-party library cannot be automatically
confined.** Something has to decide whether to run it anyway. That something is
you.

---

## The rule

**Standard library only → runs sandboxed, no questions asked.**
This is the common case for anything the agent writes on the fly: read some
files, call the model, write a result. All of that is covered by the request
vocabulary, so the plugin never needed a library in the first place.

**Anything else → you are asked once, and your answer is remembered.**
If you say yes, the plugin is trusted: it runs in-process and may import what it
likes. If you say no, it does not run. Not "runs with reduced capability" — it
does not load, and `/plugins` shows it as blocked pending your decision. There is
no middle setting, because there is no middle enforcement.

Trusting a plugin removes the *process boundary*, not the *rules*. A trusted
plugin still drives the same generator through the same interpreter: the same
tiers, the same approval gate, the same undo journal, the same ledger rows. That
is already how built-in plugins work today and it is what makes the two execution
modes interchangeable.

---

## Why the plugin's own declarations cannot be the basis for this

Plugins declare `dependencies_pip` and `dependencies_files`. It is tempting to
read those and build the trust prompt from them. That would be wrong, and the
reason matters.

Declarations exist so the package manager knows **what to install**. If a plugin
under-declares, the missing piece simply isn't there and the plugin breaks at
runtime. Being wrong is safe.

Trust decisions ask a different question: **what could this code reach?** Here,
being wrong is not safe. A plugin that declares nothing and then imports
`requests` on line 40 would sail through a declaration-based check and get
sandboxed — where its `requests` call opens a real socket that the egress gate
never sees. A careless agent produces this by accident; a hostile one produces it
on purpose. Either way the declaration is the wrong source.

So the two questions use two different sources, and they must not be confused:

| Question | Source | If it's wrong |
|---|---|---|
| What do I install? | the declarations | the plugin breaks — safe |
| What could this reach? | the actual import statements, read from the code | someone gets owned — never trust declarations here |

This is the chicken-and-egg that declarations were invented to solve, and the
resolution is that they only ever solved the first question.

---

## Why reading the imports actually works

At first glance, enumerating a file's imports by parsing looks as hopeless as
vetting a library — code can import dynamically, and then no parse is complete.

It works here because of something the sandbox already does. `__import__`,
`eval`, `exec`, and `compile` are banned names, and `importlib` and `runpy` are
not on the module allowlist. There is no way for gated code to import anything
without a literal `import` statement, and every literal import statement is
visible in the syntax tree.

That is the load-bearing point, and it is worth stating as a rule: **the import
gate is what makes the import audit complete.** If either the banned-name list or
the module allowlist is ever loosened to admit a dynamic import path, this whole
scheme quietly stops working, and nothing will visibly break at the time.

---

## A plugin is its closure, not its file

A plugin file usually isn't alone. It imports helpers, those helpers import other
helpers, and the imports that matter for trust might be several files away.

So the unit of trust is the **closure**: the plugin file plus every local file
reachable from it by following relative imports, transitively. Building it:

1. Parse the plugin file. Collect its imports.
2. Every relative import that resolves to a real file in the plugin trees is a
   local file — add it to the closure and repeat from step 1.
3. Every import that is neither relative-local nor on the stdlib allowlist is a
   third-party dependency — record it, with the file that asked for it.

The prompt is composed from step 3: which outside libraries this thing wants and
which file wants each one. A relative import that resolves to nothing is not a
security problem — that import fails at runtime — but it is worth showing, since
it usually means a helper failed to install.

**Trust binds to every file in the closure.** A plugin is trusted only if the
SHA-256 of each file in its closure is registered. This gives the revocation
behaviour for free: edit a helper three levels down, its hash changes, the plugin
that depends on it silently drops back to untrusted, and you are asked again. No
bookkeeping, no invalidation logic — a hash mismatch *is* the invalidation.

For `/packages`, the closure of an installed package is the union of the closures
of every file it installs. One prompt per package, listing every outside library
across the whole thing and what wants it.

---

## When you get asked

Three moments, all of them the same decision:

**The agent writes or edits a plugin.** The watcher's tick notices the file, the
kernel computes its closure, and if there are outside imports you are asked
before it loads. Until you answer, it does not run.

**You install a package.** `/packages install x` computes the closure across
every file the package lands — plugins and helpers alike — and asks once, before
anything is registered. Installing is not itself consent; the prompt is.

**You change your mind.** `/plugins` lists every plugin with its provenance
(built-in / installed / agent-authored), its trust state, the outside libraries
it wants, and its derived danger tier. From there you can trust or untrust
anything. Untrusting a plugin with outside imports blocks it immediately.

`/plugins` doesn't exist yet. It should, and this is what it is for — trust is
per-plugin state that needs somewhere to live, and there is currently nowhere to
see or change it.

---

## What this does not protect against

Worth being blunt, so nobody is surprised later.

**A trusted plugin can do anything.** Once you say yes, that code runs in your
process with your privileges. The requests it makes are still mediated and
audited, but nothing stops it from going around them. Saying yes is a real
decision and the prompt should read like one.

**The subprocess is not a jail.** It caps memory and CPU (`RLIMIT_AS`,
`RLIMIT_CPU`, a Windows Job Object) and it strips the namespace. It does not
restrict syscalls, files, or sockets — the child runs as you, with your
filesystem and your network. Confinement comes entirely from the import gate and
the banned builtins. That is why the gate cannot be relaxed, and why "just allow
safe libraries" is not available.

**In-process Python sandboxes have a poor track record**, ours included. The
banned-name and banned-attribute lists are the standard defences and they are
probably escapable by someone determined. This is a real limit, not a theoretical
one.

The way out of all three is the same: sandbox the child at the OS level —
AppContainer on Windows, Landlock plus seccomp on Linux, `sandbox_init` on macOS.
Then the kernel refuses the syscall instead of the parser refusing the import,
arbitrary pure-Python libraries become safe by default, and everything above
becomes a second layer rather than the only one. That is the eventual shape. This
document describes what to do until then.

---

## Deliberately unresolved

- **Prompt fatigue.** If installing a five-file package asks five questions,
  people will click yes without reading. One prompt per package, listing
  everything, is the intent — but it has not been tried on a real install yet.
- **Trusting a library rather than a plugin.** Tempting ("I already said yes to
  `requests` once") and wrong for now: the same library in different hands is a
  different risk, and the prompt is about the plugin's reach, not the library's
  reputation.
- **Revoking trust for a running plugin.** Untrusting takes effect on the next
  load. Tearing down a live in-process plugin mid-turn is a different problem.

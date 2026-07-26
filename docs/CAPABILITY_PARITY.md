# Capability-parity migration matrix

API compatibility is not required; product capability is.  A family may move
to the new runtime only when the behavior in this matrix is exercised through
an isolated worker.

| Surface | Kernel-owned mechanism | Plugin-facing mechanism | Status |
|---|---|---|---|
| Tools | invocation, schema registry, call budgets | async tool handler | kernel adapter complete; isolated acceptance pending |
| Commands and forms | state-machine phases and approval UI | async command/form handlers | pending |
| Path tasks | file queue, DAG, output commit | resource refs and typed rows | pending |
| Event tasks | event queue and subscriptions | serializable event handler | pending |
| Schedules | durable job store and clock | scoped schedule operations | pending |
| Background agents | sessions, loops, budgets, provenance | attenuated spawn request | attenuation service complete; scheduler bridge pending |
| Periodic services | service ticker | persistent actor or tick handler | pending |
| LLM providers | model routing, secrets, egress policy | brokered network/model adapter | pending |
| Embedding providers | model routing, secrets, egress policy | brokered model adapter | pending |
| Parsers | dispatch and artifact storage | input/output resource refs | pending |
| Frontends | identity binding, sessions, approvals, event bus | transport streams and render events | pending |
| Conversation hooks | ordering, loop, grants, model calls | typed observer/transform/veto | typed registry complete; loop bridge pending |
| Plugin reload | staging, verification, atomic proxy swap | no direct registry access | artifact/proxy substrate complete |
| Package install | isolated builder, lock, signatures | administrative request | lock and detached Ed25519 admission complete; builder pending |
| File access | handle resolution and transactions | `ctx.files` | read/list/stat/write/delete/move complete |
| Plugin data | namespaced store and typed views | `ctx.data` | namespaced KV and kernel views complete |
| Network | kernel-owned HTTP/stream/listener | `ctx.network` | hardened HTTP complete; streams/listeners pending |
| Shell/process | disposable confined job | `ctx.process` | SDK only; native job launcher pending |
| Responses/files | schema validation and artifact handles | `ctx.outputs` | broker-owned attachments complete |

No row is considered migrated until it passes through a verified native backend
on all three supported platforms.  This development tree deliberately reports
the native backend unavailable when its audited helper is absent.

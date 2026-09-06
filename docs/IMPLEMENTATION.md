# Implementation contracts

Cheirismos is an independent platform for governed physical agency. Its growth
does not depend on the success or availability of any one recovery target.

## Ownership

One local supervisor owns instrument access, leases, admission, budgets, durable
intent, execution, and reconciliation. Reasoning remains with existing agents.
CLI and MCP share the same typed operation registry and supervisor API.

An operator commissions a fixture and issues a bounded grant. An ordinary
agent can propose and execute reviewed experiments within that grant, but
cannot issue grants, commission fixtures, approve its own destructive plan,
or edit authoritative case state directly.

## Persistence

SQLite WAL with synchronous FULL owns authoritative state. Admission reserves
worst-case budgets and persists unique attempt identity and intent in one
transaction before physical I/O. Immutable artifacts are synchronized before
database references are committed. Recovery of an unresolved intent requires
fresh device evidence; duplicate requests never redispatch a physical attempt.

## Runtime ownership

The daemon owns service configuration, role-bound local credentials, the Unix
socket, and the lifetime of backends. `ServiceApi` authenticates a caller and
routes closed typed requests to the supervisor. The supervisor owns profiles,
grants, immutable plan review, admission, leases, budgets, durable attempt
records, and reconciliation. Device backends own only their configured
instrument sessions and emit observations through the evidence store; they do
not accept authority from a client request.

CLI and MCP are local clients of that daemon. They cannot open the SQLite
journal, artifact store, or instruments directly. Restarted service processes
recover durable state; unresolved physical work remains unknown until fresh
reconciliation evidence is recorded.

No physical fixture is commissioned at initialization. Software tests establish
software behavior only. Hardware qualification and individual device recovery
remain separately recorded evidence.

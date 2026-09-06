# Charter

Cheirismos enables an authorized agent to investigate, instrument, manipulate,
recover, validate, and document physically connected computing hardware. The
agent may act without per-effect operator confirmation only inside a bounded,
target-specific delegation established during commissioning.

## Authority

Commissioning binds a controller, target identity, fixture and instrument
identity, electrical limits, allowed effect classes, evidence location, expiry,
and revocation conditions. A grant narrows that commissioned boundary. It does
not grant arbitrary host access, arbitrary GPIO, arbitrary artifact writes, or
access to a different target.

The supervisor, not the reasoning agent, enforces exclusive leases,
preconditions, artifact identity, interlocks, budgets, durable intent,
reconciliation, and receipts. The supervisor must finish or preserve its state
when the agent disconnects.

## Rules that do not yield to autonomy

- Unknown target, pinout, voltage, power state, fixture state, or previous
  effect outcome blocks the relevant action.
- A mutation must bind an exact target, profile revision, fixture, instrument,
  approved plan, and immutable artifact digest where an artifact is involved.
- An agent cannot approve its own destructive plan or alter authoritative case
  state outside the supervisor.
- Each effect is admitted durably before physical I/O and produces evidence and
  a receipt; command success alone is insufficient.
- An interrupted or ambiguous effect enters reconciliation. Automatic replay is
  forbidden.
- Physical capability is earned per commissioned fixture. Simulation and unit
  tests establish software behavior only.

## Experiment loop

The durable loop is: observe, preserve evidence, maintain claims and competing
hypotheses, choose the least destructive discriminating experiment, review it,
execute it through the supervisor, observe its outcome, and revise the case.
Claims and hypotheses remain distinct from direct observations.

Human participation is reserved for a physical action that no commissioned
fixture can perform, such as mounting a board, moving an unactuated probe,
rework, or acquiring a marking that the available sensors cannot observe.
Cheirismos reports that handoff precisely and continues all independent work.

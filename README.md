# Cheirismos

Cheirismos is a local control plane for agents that observe, experiment on, and
manipulate physical computing devices under explicit, durable governance. It
makes a commissioned controller and fixture usable by an authorized agent while
keeping the safety boundary below the reasoning session.

The name is the Greek noun *χειρισμός*: handling or manipulation. It is used
here for deliberate handling of physical systems, not unrestricted device
access.

## What it does

Cheirismos gives agents typed operations over a device under test (DUT):
identify and observe instruments, collect and preserve evidence, propose and
review experiments, and execute admitted physical effects. It is designed for
firmware recovery, board bring-up, hardware diagnosis, validation, and other
situations where the DUT's own software may not work.

An authorized agent may work autonomously inside a target-specific delegation.
That delegation never bypasses the supervisor: a physical effect requires a
commissioned profile, active grant, independently reviewed plan, durable
journal admission, exclusive lease, and live interlocks. An interrupted effect
is unknown until reconciled from the device; it is never replayed automatically.

Cheirismos is in development. Physical capabilities require fixture
qualification and evidence for each target and instrument. Software tests do
not commission hardware or prove a physical procedure.

## Architecture and status

- [Charter](docs/CHARTER.md) defines the authority and safety model.
- [Architecture](docs/ARCHITECTURE.md) explains the supervisor, evidence, and
  execution boundary.
- [Recovery runbook](docs/RECOVERY.md) is a generic, target-neutral operating
  sequence.
- [Bench qualification](docs/QUALIFICATION.md) defines the evidence needed
  before a target grant.
- [Operations](docs/OPERATIONS.md) covers the local service, backup, and
  recovery boundary.
- [Implementation contracts](docs/IMPLEMENTATION.md) records the current
  software contracts and verified state.
- [Naming decision](docs/decisions/naming.md) and [prior-art decision](docs/decisions/prior-art.md)
  record the naming and reuse boundaries.

The platform can be developed and simulated without a particular recovery case
or bench. A physical case proceeds only when its own target, fixture, and
procedure have been qualified.

## Boundaries

Cheirismos is not a shell wrapper, a generic agent runtime, or a firmware image
repository. It does not accept arbitrary file paths as mutation inputs, issue
its own grants, or treat a successful command as proof of a successful physical
effect. Private case records, device identifiers, firmware images, credentials,
and raw captures stay outside public Git.

## License

Cheirismos has the fleet posture: **PolyForm Noncommercial 1.0.0**. The
repository license and package metadata are maintained from the fleet license
registry; consumers should rely on those rendered files for the binding terms.

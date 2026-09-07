# Decision: prior-art boundaries

**Status:** accepted

**Research refreshed:** 2026-09-07. Upstream facts and license identifiers in
this record are source-pinned observations, not legal advice.

Cheirismos reuses proven vocabulary and compatible interfaces where they fit,
while retaining ownership of physical-device authority and qualification.

- **Bus Pirate 6:** BPIO2 is the preferred protocol integration surface. Its
  bindings describe a protocol; they are not a qualified device driver,
  electrical profile, or fixture proof. Legacy Flashrom binary mode remains
  unavailable until separately qualified.
- **Numato relay:** a relay integration begins with observed module identity,
  transcript, wiring, and fail-safe state. Vendor defaults are not assumed.
- **Tekmerion:** its intent/outcome/recovery semantics inform receipt mapping,
  but it is not a current direct dependency. Its Akroasis workspace packaging
  and AGPL posture need an explicit future decision, and its tamper log does
  not provide the required fsync durability guarantee by itself.
- **Persistence:** Fjall `2.11.2` Batch is unsuitable for authoritative effect
  admission because its `write_batch` error is ignored. Cheirismos uses SQLite
  WAL with `synchronous=FULL` for the journal.
- **Fleet integration:** the workspace manifest and lockfile are the source of
  truth for current fleet dependencies. References to unreleased future
  versions are not implementation dependencies.

These boundaries keep the platform broad: no single recovery target, firmware
domain, reference board, external runtime, or unqualified instrument is a
prerequisite for case analysis and simulation.

## Researched directions, not current runtime or commissioning obligations

The following research sharpens future work. It does not add a dependency,
enable physical I/O, qualify a fixture, or change the authority boundary.

| Project | Primary upstream fact (checked 2026-09-07) | Cheirismos decision |
| --- | --- | --- |
| [flashrom](https://github.com/flashrom/flashrom) | The CLI exposes read, write, verify, layout, write-protect, and repeated-read/majority-vote controls; its [source](https://github.com/flashrom/flashrom/blob/main/cli_classic.c) identifies GPL-2.0 licensing. | Retain the typed NOR backend. Use repeated acquisition and readback as a semantic precedent, never raw agent-controlled arguments or a general flashrom subprocess. |
| [UEFITool](https://github.com/LongSoft/UEFITool) and [CHIPSEC](https://github.com/chipsec/chipsec) | UEFITool is a BSD-2-Clause UEFI image viewer/editor; CHIPSEC describes platform/BIOS/UEFI analysis and low-level interfaces, and is GPL-2.0. | Future structural UEFI parsing is bounded, offline evidence: pin tool/version digest, inputs, outputs, warnings, and resource limits. Its output never establishes compatibility, signature validity, or write authority. Do not make CHIPSEC a controller dependency. |
| [OpenHTF](https://github.com/google/openhtf) and [LAVA](https://docs.lavasoftware.org/lava/technical-references/job-definition/actions/test.html) | OpenHTF distinguishes recipes, runs, and stations and is Apache-2.0; LAVA has declared expected results and persisted job results and is GPL-2.0-or-later. | Before commissioning depends on them, add typed safety-critical measurements and versioned executable qualification/fault suites. Do not adopt either test/deployment runtime. |
| [labgrid](https://labgrid.readthedocs.io/en/latest/overview.html) | Its coordinator manages places and mutual exclusion; exporters publish availability changes, while clients access resources through exporters. Its [package metadata](https://github.com/labgrid-project/labgrid/blob/master/pyproject.toml) declares LGPL-2.1-or-later. | Do not adopt its runtime: direct client-to-exporter access violates supervisor-only handle ownership. A future multi-controller inventory may reuse only its place/topology vocabulary. |
| [Renode](https://github.com/renode/renode) and [Avatar²](https://github.com/avatartwo/avatar2) | Renode runs software on virtual boards and is MIT-licensed; Avatar² orchestrates emulator and physical targets and is Apache-2.0. | Consider Renode later only behind a simulator-evidence adapter and only for a credible target model. Do not use Avatar² as a physical backend because its debug-target control would bypass the supervisor. |

### Repeated full-read evidence

The first future evidence contract is a repeated **complete** flash acquisition.
It must preserve every source read as an immutable artifact, bind the instrument
and configuration evidence to each read, and record exact digest agreement and
any bounded mismatch report. Exact agreement is the default. A disagreement
blocks candidate authorization and every write. A majority-vote result, when a
future reviewed policy explicitly requests one, is a derived uncertain artifact;
it must never masquerade as an acquired original or satisfy the exact-agreement
precondition.

This extends the current distinction between an immutable artifact and a
physical receipt. It does not change the existing rule that interrupted effects
remain unknown and are reconciled from fresh evidence rather than replayed.

### Measurements, qualification, and research manuals

Before a dependent fixture is commissioned, safety-critical observations need a
small typed measurement envelope: quantity and unit, value or interval,
sampling time, source identity, calibration or qualification evidence, and raw
artifact digest. This narrows the current generic observation body only where
electrical or physical limits depend on it; ordinary instrument output remains
evidence rather than an inferred safety fact.

Future qualification suites should name the exact fixture and instrument,
version their required cases and expected conservative failures, and generate
the evidence cited by commissioning. They supplement, rather than replace,
independent physical measurement.

Agent-facing research manuals should retain an exact source version or hash and
page/folio citations. They should use full-text search with on-demand page
rendering through Stathmos, so a claim can be traced back to the displayed
source page. This is a documentation/evidence direction, not an authority
mechanism or a current runtime requirement.

# Decision: prior-art boundaries

**Status:** accepted

**Research expanded:** 2026-09-08. The original survey was checked on
2026-09-07; the source-pinned refinements below were checked on 2026-09-08.
Detailed research and work sequencing live in Kanon's native project planning
registry. This public record owns the product's integration boundaries.

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
| [flashrom](https://github.com/flashrom/flashrom) | The CLI exposes read, write, verify, layout, write-protect, and repeated-read/majority-vote controls. Its [source](https://github.com/flashrom/flashrom/blob/608d4c7c9bca9522ef014114981a6b1a138a4551/cli_classic.c) has GPLv2-family licensing with file-level notices. | Retain the typed NOR backend. Use repeated acquisition and readback as a semantic precedent, never raw agent-controlled arguments or a general flashrom subprocess. |
| [UEFITool](https://github.com/LongSoft/UEFITool) and [CHIPSEC](https://github.com/chipsec/chipsec) | UEFITool is a BSD-2-Clause UEFI image viewer/editor; CHIPSEC describes platform/BIOS/UEFI analysis and low-level interfaces, and is GPL-2.0. | Future structural UEFI parsing is bounded, offline evidence: pin tool/version digest, inputs, outputs, warnings, and resource limits. Its output never establishes compatibility, signature validity, or write authority. Do not make CHIPSEC a controller dependency. |
| [OpenHTF](https://github.com/google/openhtf) and [LAVA](https://docs.lavasoftware.org/lava/technical-references/job-definition/actions/test.html) | OpenHTF distinguishes recipes, runs, and stations and is Apache-2.0; LAVA has declared expected results and persisted job results and is GPL-2.0-or-later. | Before commissioning depends on them, add typed safety-critical measurements and versioned executable qualification/fault suites. Do not adopt either test/deployment runtime. |
| [labgrid](https://labgrid.readthedocs.io/en/v26.0/overview.html) | Its coordinator manages places and mutual exclusion; exporters publish availability changes, while clients access resources through exporters. Its [license](https://github.com/labgrid-project/labgrid/blob/0507604cbd6d6691f1188c7584182f1db03cbc1d/LICENSE) is LGPL-2.1-or-later. | No runtime is needed for the local controller. A future supervisor-owned client could preserve authority; agent-accessible raw control cannot. Scheduling availability must not release a durable safety lease. |
| [Renode](https://github.com/renode/renode) and [Avatar²](https://github.com/avatartwo/avatar2) | Renode runs software on virtual boards and is MIT-licensed; Avatar² orchestrates emulator and physical targets and is Apache-2.0. | Consider Renode only for a credible pinned target model and label its evidence simulated. Defer debug orchestration until a concrete workflow justifies a supervised adapter; it must not introduce a second physical authority. |

The deeper comparison adds these boundaries:

- Preserve acquisition coverage and each original before aggregation.
  flashrom can [substitute erased values for unreadable regions](https://github.com/flashrom/flashrom/blob/608d4c7c9bca9522ef014114981a6b1a138a4551/flashrom.c#L617-L657)
  under an optional policy; that output must not become an unmarked original.
- Separate observation schema/configuration from samples, following
  [Bluesky's event descriptors](https://github.com/bluesky/event-model/blob/79703246ef15fcb62e70d68e52aefd469b75ee4a/src/event_model/documents/event_descriptor.py).
  Its RunEngine's [message rewind](https://github.com/bluesky/bluesky/blob/a6a9ecfb6aefa849eeab84867e88e6025a0a6075/src/bluesky/run_engine.py#L994-L1051)
  is not Cheirismos's recovery mechanism.
- Treat discovery and queries according to their effects. Debug attach can
  [assert reset](https://github.com/probe-rs/probe-rs/blob/c7903cb163cd0cfaac0dd69fb49a6f26d62fd958/probe-rs/src/probe.rs#L407-L452),
  and SCPI [error queries consume queue entries](https://github.com/pymeasure/pymeasure/blob/68bd427d69620e02ce887495851e3fee812f6dd1/pymeasure/instruments/generic_types.py#L86-L110).
  Fixed semantic drivers must bound such operations and polling loops.
- Evaluate [UEFIExtract report mode](https://github.com/LongSoft/UEFITool/blob/dac91b26733ca21cb204e41614c1b8c81cc50860/UEFIExtract/uefiextract_main.cpp#L71-L119)
  as the first contained offline adapter. Device access, credentials, network,
  unrelated host/private files, writable authoritative state and unbounded
  output must be absent from the transform process. Use digest-verified staged
  inputs, not evidence-store paths. Source inspection is not adapter qualification.

### Repeated full-read evidence

The first future evidence contract is a repeated **complete** flash acquisition.
It must preserve every source read as an immutable artifact, bind the instrument
and configuration evidence to each read, and record exact digest agreement and
any bounded mismatch report. Distinct attempts must be verified from their
receipts, not inferred from filenames or duplicate artifact references. Exact
agreement is the default requirement of a dependent target-recovery policy;
disagreement blocks that policy's candidate authorization and erase/write.
Offline candidate construction and unrelated qualification patterns remain
separate. Agreement proves repeatability, not correct wiring or authentic bytes.
Simulated acquisitions cannot establish physical recovery eligibility.
A majority-vote result, when a future reviewed policy explicitly requests one,
is a derived uncertain artifact;
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
independent physical measurement. A fault case can pass because an effect
correctly remains unknown while the fixture still requires reconciliation.
Skipped or missing required cases cannot disappear from the verdict, and a
passing simulated suite cannot commission a physical capability. Qualification
execution itself needs an independently justified, limited sacrificial-fixture
profile and reviewed authority through the existing supervisor.

Agent-facing research manuals should retain an exact source version or hash and
page/folio citations. They should use full-text search with on-demand page
rendering following Stathmos's approach, so a claim can be traced back to the displayed
source page. This is a documentation/evidence direction, not an authority
mechanism or a current runtime requirement.

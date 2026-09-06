# Decision: prior-art boundaries

**Status:** accepted

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
- **Fleet integration:** Epitelesis `0.4.1` and Koinon `0.2.1` are the available
  integration baselines. References to unreleased future versions are not
  implementation dependencies.

These boundaries keep the platform broad: no single recovery target, firmware
domain, reference board, external runtime, or unqualified instrument is a
prerequisite for case analysis and simulation.

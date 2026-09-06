# Cheirismos

Governed physical device observation, experimentation, and manipulation for agents.

Fleet contributors read Kanon's `crates/basanos/standards/STANDARDS.md` and
`RUST.md` before editing Rust. A local ignored `standards/` mirror may be
available; the private fleet corpus is not distributed with this repository.
The canonical product plan is in Kanon; `docs/IMPLEMENTATION.md` records the
current implementation contracts and verified state.

The root coordinator owns integration. Delegated editing, reproduction, build,
formatting, and testing workers must create a named Git worktree and confirm
its path and branch before changing files or running Cargo. Other agents may
share repository state: never overwrite or revert unrelated work. Run one
Cargo command at a time per worktree; use `env -u CARGO_TARGET_DIR cargo ...`
to keep output local. Do not delegate recursively without a concrete brief.

Physical device access belongs to the supervisor. Never access real hardware
from tests or enable a target before its fixture is commissioned. Preserve
unknown effects across interruption. No unconditional replay or synthetic
success receipts. Private case data and firmware never enter public Git.

Use conventional commits. Attach a Gate-Passed trailer only after the named
gate succeeds. Keep product documentation accurate about software support,
simulation, and physical qualification.

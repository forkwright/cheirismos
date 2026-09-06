# Cheirismos

Cheirismos governs agent observation, experimentation, and manipulation of
physical devices. Read [AGENTS.md](AGENTS.md) before changing code or running
commands that could reach a device.

## Boundaries

- Tests and development use fixtures or simulation. Real hardware access is
  supervisor-owned and requires an explicitly commissioned target.
- Preserve an interrupted operation as unknown until its recovery procedure
  establishes a new state. Do not replay it automatically.
- Keep device protocol and firmware detail inside an instrument boundary;
  common lifecycle, authorization, evidence, and receipt semantics belong in
  the core.
- Never commit credentials, private case data, firmware, or target-specific
  operating records.

## Structure

- `src/`: application and common governance types.
- `docs/IMPLEMENTATION.md`: current implementation contracts and verified
  state.

Fleet contributors read `STANDARDS.md` and `RUST.md` in their local Kanon
checkout's `crates/basanos/standards/`. Keep any local standards mirror ignored.

## Commands

```bash
env -u CARGO_TARGET_DIR cargo fmt --check
env -u CARGO_TARGET_DIR cargo test
```

Use conventional commits. Add a `Gate-Passed:` trailer only after the named
gate succeeds.

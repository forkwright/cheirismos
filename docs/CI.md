# Repository validation

The required `gate / gate` check comes from the pinned fleet hybrid workflow.
It validates a local gate attestation or runs formatting, compilation, strict
Clippy, nextest, and doctests. Main pushes run the integrated code through the
build path. Security and CodeQL run separately. Main protection requires a pull
request and the GitHub Actions application-bound gate check, with the fleet's
administrator exemption retained. Force pushes and branch deletion are disabled.

## Private standards lint

The separate `kanon lint` job checks accepted main commits against the private
Kanon revision pinned in the workflow. It is not a required pull-request check.
Pull requests do not receive the private standards credential or checkout.
Fleet contributors run Kanon lint locally before landing changes.

The `kanon-standards` GitHub environment permits only the `main` branch. Its
`KANON_STANDARDS_READ_KEY` secret is a dedicated SSH deploy key with read-only
access to the Kanon repository alone. It is an environment secret, not a
repository or organization secret. Missing access fails the main job.

Accepted main workflow code is trusted with this environment's access; the
branch restriction does not constrain what an authorized main workflow can do.
Review workflow changes with that access in mind.

Kanon is built on a separate ephemeral hosted runner without caching. The
checkout does not persist its credential. Private source contents, build
products, compiler diagnostics, and lint findings stay on that runner and are
never uploaded as public artifacts or annotations. The job reports checkout
and toolchain versions. A failed job reports the failing stage; a
fleet contributor reproduces it privately using the pinned revision:

```bash
kanon lint . --summary --min-severity error
```

Rotate access by creating a new read-only Kanon deploy key, replacing the
environment secret, verifying a main run, then revoking the old deploy key.
Keep the environment's exact branch restriction in place. Do not replace this
credential with an account token or give it write access.

## Releases

Release Please proposes the changelog and version record. Review and validate
the final release pull request after dependency changes settle, then merge it
through ordinary protection. A pull request created with `GITHUB_TOKEN` may
have no workflow runs because GitHub suppresses recursive events. An authorized
maintainer can close and reopen the final proposal to trigger its normal checks;
an empty check list is never validation.

A software release does not commission a fixture or qualify an instrument.
Physical readiness remains governed by [QUALIFICATION.md](QUALIFICATION.md).

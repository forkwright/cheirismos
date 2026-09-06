# Operations

Cheirismos runs one local supervisor for each private instance. The supervisor
owns durable intent, evidence, instrument access, and recovery. It has no TCP
listener. A local client presents a role credential over its Unix socket; the
service authenticates the credential and the peer identity before accepting a
request.

## Deployment boundary

`deploy/` installs a Linux controller service. Verify deployment on its actual
host using the startup and health checks below. Installation and service health
do not establish fixture qualification.

The intended installation identity is deliberately split:

| Identity | Membership | Purpose |
| --- | --- | --- |
| `cheirismos` | primary `cheirismos`; supplementary `cheirismos-hardware` and `cheirismos-clients` in the unit | Supervisor; owns state, may access commissioned device nodes, and may assign its socket to the client group. |
| local client accounts | `cheirismos-clients`, never `cheirismos-hardware` | Hold a role-specific token and make authenticated requests. |
| `root` | installation only | Installs unit and exact device rules; does not hold service credentials. |

`ServiceConfig` supports only a mode-0600 private socket or a mode-0660
socket with an explicit `socket_group_gid`. Development initialization uses the
private mode and same-UID credentials. A deployed instance must place its socket
under the separate `/run/cheirismos/` runtime parent, set mode 0660, set a
nonempty `socket_group_gid` for `cheirismos-clients`, and bind each role
credential to its intended client peer UID. The runtime parent must already be
owned by the service UID and must not be group- or world-writable. The durable
instance, credentials, evidence, and database stay under `/var/lib/cheirismos`
and remain inaccessible to client accounts.

This split is a release gate: client accounts may join `cheirismos-clients` but
never `cheirismos-hardware`; do not loosen the exact udev rule. Verify the
socket owner, group, and mode after startup. The authoritative configuration
shape is emitted by `cheirismos schema --service-config`; `cheirismos schema`
continues to emit the closed client-request schema.

## Install an uncommissioned platform

Build the reviewed revision on a Linux system compatible with the controller:

```bash
cargo build --release --locked --bin cheirismos
sha256sum target/release/cheirismos
```

On the target host, copy the repository deployment directory and a reviewed
release binary, then install the platform without a device rule:

```bash
sudo ./deploy/install.sh --binary /path/to/cheirismos
```

The installer creates the dedicated service account, private
`/var/lib/cheirismos` root, and systemd unit. It does not enable or start the
unit and it does not configure an instrument. The service can run in this state
for local status, artifact, case, and planning work; it admits no physical work
until an instrument and a commissioned profile are configured.

Before enabling, have the supervisor create its instance while running as the
service account. This produces a mode-0700 instance root, mode-0600
`service.json`, and separate mode-0600 `operator`, `reviewer`, and `agent`
token files. Keep the service's bootstrap copies below `/var/lib/cheirismos`;
never place a token in `/etc`, shell history, a unit `Environment=`, journal
output, Git, or a backup log.

```bash
sudo -u cheirismos /usr/local/bin/cheirismos init /var/lib/cheirismos
sudo stat -c '%a %U:%G %n' /var/lib/cheirismos \
  /var/lib/cheirismos/service.json \
  /var/lib/cheirismos/credentials
sudo systemd-analyze verify /etc/systemd/system/cheirismos.service
sudo systemd-analyze security cheirismos.service
```

`StateDirectory=cheirismos` may create the empty private root before this
command. Initialization accepts that directory only when it is empty,
mode-0700, owned by `cheirismos`, and not a symlink. It refuses any existing
credentials or other contents.

The unit creates `/run/cheirismos` as a service-owned mode-0755 runtime
directory on every start. Configure the service-owned `service.json` during
authorized offline maintenance with the external socket, its group GID, and
the intended peer UID for every role binding. A deployed configuration uses:

```bash
sudo -u cheirismos /usr/local/bin/cheirismos schema --service-config
```

```json
{
  "socket": "/run/cheirismos/service.sock",
  "socket_mode": 432,
  "socket_group_gid": 1234
}
```

Here `432` is octal `0660`, and `1234` must be the value from
`getent group cheirismos-clients`. Each credential binding's `peer_uid` must
match its local client account. The service account's supplementary
`cheirismos-clients` membership lets it assign that group after binding. Keep
the durable database and evidence under `/var/lib/cheirismos`; distribute a
role token to its bound client only through an approved local secret-delivery
path, mode 0600, without printing it or placing it in shell history, a unit,
or logs.

Then reload and enable the ready, still-uncommissioned service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cheirismos.service
sudo stat -c '%a %U:%G %n' /run/cheirismos /run/cheirismos/service.sock
```

To add a hardware binding later, rerun the installer with an exact reviewed
serial pair:

```bash
sudo ./deploy/install.sh \
  --binary /path/to/cheirismos \
  --serial EXACT_SERIAL_FROM_COMMISSION_RECORD \
  --device-link commissioned-fixture
sudo udevadm control --reload-rules
sudo udevadm test "$(udevadm info -q path -n /dev/cheirismos/commissioned-fixture)"
```

This creates one rule at
`/etc/udev/rules.d/99-cheirismos-commissioned-fixture.rules`. The rule matches
only `SUBSYSTEM=="tty"` and that literal serial; it does not match a USB vendor,
product, or tty family. Its device is group-readable only by
`cheirismos-hardware`. Configure the instrument through the reviewed service
configuration and add an exact
`DeviceAllow=/dev/cheirismos/commissioned-fixture rw` drop-in only after the
stable symlink is present and verified.

See [QUALIFICATION.md](QUALIFICATION.md) before issuing a target grant.

## Health, restart, and recovery

A healthy process is insufficient proof that a physical operation completed.
Use the authenticated `status` command with the least-privileged appropriate
credential, inspect the journal, and reconcile unresolved work against fresh
device evidence:

```bash
sudo systemctl status cheirismos.service
sudo journalctl -u cheirismos.service -b --no-pager
sudo -u cheirismos /usr/local/bin/cheirismos status \
  /run/cheirismos/service.sock \
  /var/lib/cheirismos/credentials/reviewer.token
```

`Restart=on-failure` restores the supervisor process only. It must resume
unresolved physical work as **unknown**, never replay it. A restart or a failed
health check requires an operator to compare durable intent, evidence, and the
fixture before any new operation is admitted. Stop the service before an
instrument is unplugged or its udev rule is changed.

If a grant expires or is revoked before dispatch or between completed steps,
an operator can submit `transaction/abandon_halted_run` with the exact run,
grant, plan, immutable request ID, and a justification artifact digest. The
supervisor records the decision, rejects remaining undispatched intents, closes
that authority pair permanently, and releases its owned resources atomically.
It preserves completed receipts and consumed budgets. An in-flight, partial, or
unknown effect prevents abandonment and still requires fresh reconciliation or
a separately reviewed recovery takeover.

A recovery run also holds the uncertainty inherited from its source. It cannot
be abandoned, and a rejection before its first effect does not free those
resources. An operator may transfer that responsibility to another separately
reviewed recovery plan. The takeover request's `unresolved` attempts may identify
an undispatched, rejected, or completed-prefix attempt only when it belongs to
a recorded recovery destination that still owns the exact resource leases.
No attempt or reconciliation in the source grant and plan may be in flight.
The transaction transfers the leases and permanently retires the source
authority; the source can never resume or reacquire them. Original receipts and
consumed budgets remain intact throughout the chain. Generate the request
shape with `cheirismos schema`.

## Credential rotation

The current target API does not yet expose a credential-rotation command.
Authorized offline maintenance may update a role's local token and its binding
digest while the supervisor is stopped, then restart the service. The change
must preserve the durable SQLite state, evidence store, grants, and revocation
records; credential maintenance must never initialize a replacement instance
or remove those records. The implementation has no separate credential-
revocation history: changing the configured digest is what makes the prior
token fail after restart. Verify that rejection and the replacement through
authenticated requests. Token readers never receive hardware-group membership,
and every delivered token remains mode 0600 and is never printed or logged.

## Backup and restore

Stop the supervisor before an offline copy so SQLite, evidence, config, and
credential bindings describe one point in time. Credentials are sensitive: use
the target's encrypted backup mechanism and restrict its restore destination to
root and the service account.

```bash
sudo systemctl stop cheirismos.service
sudo tar --xattrs --acls -C /var/lib -cpf /secure/backup/cheirismos.tar cheirismos
sudo systemctl start cheirismos.service
```

Restore into a staging directory while the service remains stopped. The current
service has no separate recovery command or database-repair mode: its concrete
restore check is opening the restored private configuration and durable state as
the service account, then making an authenticated `status` request after
startup. Preserve the prior instance until that check and the fixture-evidence
review have completed.

```bash
sudo install -d -m 0700 -o root -g root /var/lib/cheirismos.restore
sudo tar --xattrs --acls -C /var/lib/cheirismos.restore -xpf /secure/backup/cheirismos.tar
sudo chown -R cheirismos:cheirismos /var/lib/cheirismos.restore/cheirismos
sudo mv /var/lib/cheirismos /var/lib/cheirismos.pre-restore
sudo mv /var/lib/cheirismos.restore/cheirismos /var/lib/cheirismos
sudo systemctl start cheirismos.service
sudo -u cheirismos /usr/local/bin/cheirismos status \
  /run/cheirismos/service.sock \
  /var/lib/cheirismos/credentials/reviewer.token
```

Do not restore over a live instance. A restored unresolved intent remains
unknown; it never authorizes a replay of physical I/O.

## Disposable simulator verification

The repository includes one authenticated daemon test for two filesystem-backed
disposable targets. It inventories and commissions a flash and relay simulator,
imports typed case evidence, independently reviews immutable plans, verifies a
NOR write/readback and relay sequence, rejects an unauthorized commissioning
request, then restarts from an offline instance copy. It opens no hardware.

```bash
CARGO_BUILD_JOBS=4 NEXTEST_TEST_THREADS=4 env -u CARGO_TARGET_DIR \
  cargo test --jobs 4 --test e2e_simulator
```

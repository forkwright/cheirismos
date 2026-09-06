#!/usr/bin/env bash
# Install Cheirismos deployment artifacts on the Linux controller without accessing devices.
set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

usage() {
  cat <<'USAGE'
Usage: sudo deploy/install.sh --binary PATH [--serial ID_SERIAL_SHORT --device-link NAME]

Installs the system account, private state root, and service unit. Supplying
both serial options also installs one exact-serial udev rule. It neither
enables the service nor configures an instrument, so an uncommissioned
platform can be initialized and started before devices are attached.
USAGE
}

binary=''
serial=''
device_link=''
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
while (($#)); do
  case $1 in
    --binary) binary=${2:?--binary needs a path}; shift 2 ;;
    --serial) serial=${2:?--serial needs an ID_SERIAL_SHORT}; shift 2 ;;
    --device-link) device_link=${2:?--device-link needs a name}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

cd -- "$repo_root"

[[ -n "$binary" ]] || { usage >&2; exit 2; }
[[ -x "$binary" && ! -L "$binary" ]] || { printf 'binary must be an executable regular file\n' >&2; exit 2; }
if [[ -n "$serial" || -n "$device_link" ]]; then
  [[ -n "$serial" && -n "$device_link" ]] || {
    printf '%s\n' 'serial and device-link must be supplied together' >&2
    usage >&2
    exit 2
  }
  [[ $serial =~ ^[A-Za-z0-9._-]+$ ]] || { printf 'serial has unsafe characters\n' >&2; exit 2; }
  [[ $device_link =~ ^[A-Za-z0-9._-]+$ ]] || { printf 'device link has unsafe characters\n' >&2; exit 2; }
fi

install -d -o root -g root -m 0755 /etc/cheirismos
getent group cheirismos-hardware >/dev/null || groupadd --system cheirismos-hardware
getent group cheirismos-clients >/dev/null || groupadd --system cheirismos-clients
getent group cheirismos >/dev/null || groupadd --system cheirismos
id -u cheirismos >/dev/null 2>&1 || useradd --system --home-dir /var/lib/cheirismos --shell /usr/sbin/nologin --gid cheirismos cheirismos
install -d -o cheirismos -g cheirismos -m 0700 /var/lib/cheirismos
install -o root -g root -m 0755 "$binary" /usr/local/bin/cheirismos
install -o root -g root -m 0644 deploy/systemd/cheirismos.service /etc/systemd/system/cheirismos.service

if [[ -n "$serial" ]]; then
  install -d -o root -g root -m 0755 /dev/cheirismos
  rule=/etc/udev/rules.d/99-cheirismos-"$device_link".rules
  sed -e "s/@SERIAL@/$serial/g" -e "s/@DEVICE_LINK@/$device_link/g" \
    deploy/udev/99-cheirismos-serial.rules.template >"$rule"
  chmod 0644 "$rule"
else
  printf '%s\n' 'Installed without a device rule; the service may run uncommissioned.'
fi
systemctl daemon-reload
printf '%s\n' 'Installed but not enabled. Continue with docs/OPERATIONS.md on the target host.'

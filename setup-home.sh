#!/usr/bin/env bash
# Run on the home Ubuntu Linux host, not Oracle or OPNsense.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run: sudo bash setup-home.sh' >&2; exit 1; }
. /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || {
    echo 'This home installer targets Ubuntu 24.04. Do not run it on OPNsense.' >&2
    exit 1
}
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
apt-get update
apt-get --no-remove install -y python3 ca-certificates
if ! id oracle-edge >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin oracle-edge
fi
if systemctl cat oracle-edge-failover.service >/dev/null 2>&1; then
    systemctl disable --now oracle-edge-failover.service
fi
if systemctl cat oracle-edge-watchdog.service >/dev/null 2>&1; then
    systemctl stop oracle-edge-watchdog.service
fi
install -d -o root -g oracle-edge -m 750 /etc/oracle-edge
install -d -o root -g root -m 755 /usr/local/lib/oracle-edge
install -d -o oracle-edge -g oracle-edge -m 700 /var/lib/oracle-edge
if [[ -f /etc/oracle-edge/watchdog.json || -f /etc/oracle-edge/cf-token ]]; then
    backup_dir=$(mktemp -d /etc/oracle-edge/backup.XXXXXXXX)
    for name in watchdog.json cf-token; do
        if [[ -f /etc/oracle-edge/$name ]]; then
            cp -p "/etc/oracle-edge/$name" "$backup_dir/$name"
        fi
    done
    printf 'Previous local credentials/config backed up to %s\n' "$backup_dir"
fi
install -o root -g root -m 644 watchdog.py configure-home.py /usr/local/lib/oracle-edge/
python3 -I /usr/local/lib/oracle-edge/configure-home.py
install -o root -g root -m 644 oracle-edge-watchdog.service /etc/systemd/system/oracle-edge-watchdog.service
systemd-analyze verify /etc/systemd/system/oracle-edge-watchdog.service
systemctl daemon-reload
trap 'chown -R oracle-edge:oracle-edge /var/lib/oracle-edge' EXIT
python3 -I /usr/local/lib/oracle-edge/watchdog.py --config /etc/oracle-edge/watchdog.json --check
echo 'Preflight passed. The watchdog is installed but NOT running; DNS is unchanged.'
echo 'Continue with docs/INSTALL.md (systemd option) to switch and enable automation.'

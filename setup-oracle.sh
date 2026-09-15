#!/usr/bin/env bash
# Dedicated Ubuntu 24.04 OCI VM. DNS is never changed by this installer.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run with sudo, preserving SSH_CONNECTION.' >&2; exit 1; }
. /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || { echo 'Requires Ubuntu 24.04.' >&2; exit 1; }
[[ -n ${SSH_CONNECTION:-} ]] || { echo 'Use: sudo env "SSH_CONNECTION=$SSH_CONNECTION" bash setup-oracle.sh' >&2; exit 1; }
admin_ip=$(python3 - "$SSH_CONNECTION" <<'PY'
import ipaddress, sys
fields = sys.argv[1].split()
if len(fields) != 4 or fields[3] != '22':
    raise SystemExit('Requires an existing IPv4 SSH session on port 22.')
address = ipaddress.ip_address(fields[0])
if address.version != 4:
    raise SystemExit('Use an IPv4 SSH connection for this IPv4-only profile.')
print(address)
PY
)
for manager in ufw firewalld nftables docker; do
    if systemctl is-active --quiet "$manager.service"; then
        echo "Existing $manager manager is active. Use its existing policy or a clean dedicated VM." >&2
        exit 1
    fi
done
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
[[ -f runtime/haproxy.cfg ]] || { echo 'First run: python3 configure-oracle.py' >&2; exit 1; }
bash ./preflight-oracle.sh
systemctl mask nftables.service
apt-get update
apt-get --no-remove install -y haproxy ca-certificates curl iptables iptables-persistent nftables unattended-upgrades
backup_dir=$(mktemp -d /root/tls-edge-failover-config-backup.XXXXXXXX)
cp -a /etc/haproxy "$backup_dir/"
printf 'Existing HAProxy configuration saved to %s\n' "$backup_dir"
haproxy -c -f runtime/haproxy.cfg
install -o root -g root -m 644 runtime/haproxy.cfg /etc/haproxy/haproxy.cfg
install -d -m 755 /etc/systemd/system/haproxy.service.d
install -o root -g root -m 644 haproxy-systemd.conf /etc/systemd/system/haproxy.service.d/limits.conf
haproxy -c -f /etc/haproxy/haproxy.cfg
systemctl daemon-reload
systemctl enable --now haproxy
systemctl reload haproxy
bash ./install-firewall.sh "$admin_ip/32"
printf '\nOracle relay uses runtime/haproxy.cfg. Cloudflare DNS is unchanged.\n'
printf 'Complete the NEW SSH and HTTPS tests before the firewall rollback timer expires.\n'

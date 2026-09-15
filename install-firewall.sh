#!/usr/bin/env bash
# Dedicated OCI Ubuntu 24.04 only. Run on Oracle, not on your home firewall.
# Requires existing iptables, nftables, netfilter-persistent, Python and systemd.
set -Eeuo pipefail
umask 077

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'Run as root, preserving SSH_CONNECTION when using sudo.'
[[ $# -ge 1 && $# -le 2 ]] || die 'Usage: install-firewall.sh ADMIN_IPV4_CIDR [--console]'
[[ ${2:-} == '' || ${2:-} == --console ]] || die 'Only --console is supported as the second argument.'
for executable in python3 iptables ip6tables iptables-save ip6tables-save iptables-restore ip6tables-restore nft systemctl systemd-run netfilter-persistent; do
    command -v "$executable" >/dev/null || die "Required command missing: $executable"
done
[[ -r /etc/os-release ]] || die 'Cannot identify the operating system.'
. /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || die 'This helper requires Ubuntu 24.04.'
[[ $(iptables --version) == *nf_tables* && $(ip6tables --version) == *nf_tables* ]] || die 'Expected the stock iptables-nft backend for both families.'
[[ -n ${SSH_CONNECTION:-} || ${2:-} == --console ]] || die 'SSH_CONNECTION is absent. Preserve it through sudo, or use --console only from the OCI console.'
admin_cidr=$(python3 - "$1" "${SSH_CONNECTION:-}" <<'PY'
import ipaddress, sys
network = ipaddress.ip_network(sys.argv[1], strict=False)
if network.version != 4:
    raise SystemExit('The administrator CIDR must be IPv4.')
if network.prefixlen == 0:
    raise SystemExit('Refusing unrestricted public SSH; use your administrator /32 or trusted network.')
if sys.argv[2]:
    fields = sys.argv[2].split()
    if len(fields) != 4:
        raise SystemExit('Malformed SSH_CONNECTION.')
    if fields[3] != '22':
        raise SystemExit('This helper permits SSH port 22 only; current SSH uses another port.')
    source = ipaddress.ip_address(fields[0])
    if source.version != 4 or source not in network:
        raise SystemExit('Current SSH source is outside the administrator IPv4 CIDR.')
print(network)
PY
)

for manager in ufw firewalld nftables docker; do
    if systemctl is-active --quiet "$manager.service"; then
        die "Competing service is active: $manager. Use a fresh dedicated VM."
    fi
done
command -v docker >/dev/null && die 'Docker is installed; this helper is for a dedicated VM without Docker.'
rules_v4=$(iptables-save 2>&1)
rules_v6=$(ip6tables-save 2>&1)
rule_inventory="$rules_v4$rules_v6"
[[ $rule_inventory != *Warning* && $rule_inventory != *incompatible* ]] || die 'iptables reports incompatible/native or legacy rules; inspect manually.'
[[ $rule_inventory != *EDGE_INPUT* && $rule_inventory != *DOCKER* && $rule_inventory != *ufw-* ]] || die 'Existing edge, Docker or UFW chains found; refusing to overwrite them.'
nft -j list tables | python3 -c '
import json, sys
allowed = {"filter", "nat", "mangle", "raw", "security"}
for item in json.load(sys.stdin)["nftables"]:
    table = item.get("table")
    if table and (table["family"] not in {"ip", "ip6"} or table["name"] not in allowed):
        raise SystemExit("Unexpected native nftables table; inspect manually: " + str(table))
'

backup_dir=$(mktemp -d /root/oracle-edge-backup.XXXXXXXX)
iptables-save >"$backup_dir/live.v4"
ip6tables-save >"$backup_dir/live.v6"
for family in v4 v6; do
    if [[ -e /etc/iptables/rules.$family ]]; then
        cp /etc/iptables/rules."$family" "$backup_dir/persistent.$family"
    else
        touch "$backup_dir/persistent.$family.absent"
    fi
done
chmod 600 "$backup_dir"/*
unit_name="oracle-edge-rollback-$(date +%s)-$$"
printf 'BACKUP_DIR=%q\n' "$backup_dir" >"$backup_dir/rollback.env"
cat >"$backup_dir/rollback.sh" <<'ROLLBACK'
#!/usr/bin/env bash
set -uo pipefail
umask 077
. "$(dirname "$0")/rollback.env"
result=0
# Restore both complete pre-change rulesets, retaining OCI OUTPUT protections.
iptables-restore --wait 10 <"$BACKUP_DIR/live.v4" || result=1
ip6tables-restore --wait 10 <"$BACKUP_DIR/live.v6" || result=1
for family in v4 v6; do
    if [[ -f $BACKUP_DIR/persistent.$family.absent ]]; then
        rm -f /etc/iptables/rules."$family" || result=1
    else
        mkdir -p /etc/iptables || result=1
        install -m 600 "$BACKUP_DIR/persistent.$family" /etc/iptables/rules."$family" || result=1
    fi
done
exit "$result"
ROLLBACK
chmod 700 "$backup_dir/rollback.sh"
rollback_on_error() {
    local result=$1
    trap - ERR INT TERM
    printf 'Installation failed; restoring backups from %s\n' "$backup_dir" >&2
    if bash "$backup_dir/rollback.sh"; then
        systemctl stop "$unit_name.timer" 2>/dev/null || true
    else
        printf 'Rollback reported an error; use the OCI console. Timer remains armed.\n' >&2
    fi
    exit "$result"
}
trap 'rollback_on_error $?' ERR
trap 'rollback_on_error 130' INT
trap 'rollback_on_error 143' TERM

# Arm recovery before making any rule changes. Nothing is persisted yet.
systemd-run --unit="$unit_name" --on-active=180s --timer-property=AccuracySec=1s \
    --property=Type=oneshot /bin/bash "$backup_dir/rollback.sh"
systemctl is-active --quiet "$unit_name.timer"

# Build unattached chains. Existing INPUT paths remain effective during staging.
iptables --wait 10 -N EDGE_INPUT
ip6tables --wait 10 -N EDGE_INPUT6
for family in v4 v6; do
    if [[ $family == v4 ]]; then
        firewall=iptables
        chain=EDGE_INPUT
    else
        firewall=ip6tables
        chain=EDGE_INPUT6
    fi
    "$firewall" --wait 10 -A "$chain" -i lo -j ACCEPT
    "$firewall" --wait 10 -A "$chain" -m conntrack --ctstate INVALID -j DROP
    "$firewall" --wait 10 -A "$chain" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    if [[ $family == v4 ]]; then
        "$firewall" --wait 10 -A "$chain" -p icmp -j ACCEPT
        "$firewall" --wait 10 -A "$chain" -p udp --sport 67 --dport 68 -j ACCEPT
        "$firewall" --wait 10 -A "$chain" -s "$admin_cidr" -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
        "$firewall" --wait 10 -A "$chain" -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
    else
        "$firewall" --wait 10 -A "$chain" -p ipv6-icmp -j ACCEPT
        "$firewall" --wait 10 -A "$chain" -p udp --sport 547 --dport 546 -j ACCEPT
    fi
    "$firewall" --wait 10 -A "$chain" -j DROP
done
# Within each family the completed chain becomes live with one head insertion.
iptables --wait 10 -I INPUT 1 -j EDGE_INPUT
ip6tables --wait 10 -I INPUT 1 -j EDGE_INPUT6
trap - ERR INT TERM

cat <<INSTRUCTIONS
Firewall active temporarily. Automatic rollback is armed for 180 seconds.
Backup and manual rollback: sudo bash '$backup_dir/rollback.sh'

Before that deadline, keep this session open and test from a NEW terminal:
  ssh YOUR_ORACLE_USER@ORACLE_PUBLIC_IP
  curl --fail --resolve YOUR_HOST:443:ORACLE_PUBLIC_IP https://YOUR_HOST/
The relay must already be running for the curl check to pass.
Also confirm unauthorized sources cannot open SSH; IPv6 has no new TCP ingress.

Only after the tests pass, run ON ORACLE:
  sudo systemctl stop '$unit_name.timer'
  sudo systemctl is-active '$unit_name.service'
The service must be inactive, not activating/active. If rollback already ran,
or the timer expired, DO NOT save: inspect the live rules and rerun the helper.
  sudo iptables -C INPUT -j EDGE_INPUT
  sudo ip6tables -C INPUT -j EDGE_INPUT6
  sudo netfilter-persistent save

No rules have been persisted and the rollback timer has not been cancelled.
INSTRUCTIONS

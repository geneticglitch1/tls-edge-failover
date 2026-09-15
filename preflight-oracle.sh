#!/usr/bin/env bash
# Read-only checks. Run before package installation, masking units or replacing config.
set -Eeuo pipefail
die() { printf 'Preflight stopped: %s\n' "$*" >&2; exit 1; }
for command_name in iptables-save ip6tables-save nft python3 systemctl dpkg-query; do
    command -v "$command_name" >/dev/null || die "Missing inspection tool: $command_name; inspect this VM before installing firewall packages."
done
for manager in ufw firewalld nftables docker; do
    if systemctl is-active --quiet "$manager.service"; then
        die "$manager is active. No changes made; retain and inspect its existing policy."
    fi
done
command -v docker >/dev/null && die 'Docker is installed; automatic firewall replacement is not supported.'
ufw_status=$(dpkg-query -W -f='${Status}' ufw 2>/dev/null || true)
[[ $ufw_status != 'install ok installed' ]] || die 'UFW is installed, even if inactive. No packages will be removed; inspect the current firewall first.'
rules_v4=$(iptables-save 2>&1) || die 'Cannot read IPv4 rules.'
rules_v6=$(ip6tables-save 2>&1) || die 'Cannot read IPv6 rules.'
inventory="$rules_v4$rules_v6"
[[ $inventory != *Warning* && $inventory != *incompatible* ]] || die 'Incompatible/native firewall rules need inspection.'
[[ $inventory != *EDGE_INPUT* && $inventory != *DOCKER* && $inventory != *ufw-* ]] || die 'Existing edge, Docker or UFW chains found. No changes made; inspect them first.'
nft -j list tables | python3 -c '
import json, sys
allowed = {"filter", "nat", "mangle", "raw", "security"}
for item in json.load(sys.stdin)["nftables"]:
    table = item.get("table")
    if table and (table["family"] not in {"ip", "ip6"} or table["name"] not in allowed):
        raise SystemExit("Preflight stopped: native nftables table needs inspection: " + str(table))
'
printf 'Read-only firewall preflight passed.\n'

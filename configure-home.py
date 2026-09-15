#!/usr/bin/env python3
"""Interactive local configuration. Reads Cloudflare DNS; never changes DNS."""
import getpass
import argparse
import grp
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from watchdog import APIError, Cloudflare, SafetyError, canonical_name, public_v4, load_config, observed_mode, validate_inventory


def private_write(path, text, mode, gid=None):
    fd, tmp = tempfile.mkstemp(prefix=".configure-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), mode)
            if gid is not None:
                os.fchown(stream.fileno(), 0, gid)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local", action="store_true", help="Save private runtime files beside this script; no sudo/systemd needed")
    parser.add_argument("--health-host", help="Permanent proxied health hostname (default: edge-health.<domain>)")
    parser.add_argument("--app", action="append", help="Existing A record to manage; repeat as needed (default: apex and wildcard)")
    args = parser.parse_args()
    if not args.local and os.geteuid() != 0:
        raise SafetyError("Use --local without sudo, or run the optional system installer")
    directory = Path(__file__).resolve().parent / "runtime" if args.local else Path("/etc/oracle-edge")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.local:
        os.chmod(directory, 0o700)
    domain = canonical_name(input("Cloudflare domain (for example, example.com): ").strip())
    oracle_ip = public_v4(input("Oracle reserved public IPv4: ").strip())
    home_ip = public_v4(input("Current home public IPv4: ").strip())
    if oracle_ip == home_ip:
        raise SafetyError("Oracle and home IPv4 addresses must differ")
    health_host = canonical_name(args.health_host or "edge-health." + domain)
    apps = [canonical_name(name, allow_wildcard=True) for name in (args.app or ["*." + domain, domain])]
    if any(name != domain and not name.endswith("." + domain) for name in [health_host, *apps]):
        raise SafetyError("All configured names must belong to the chosen domain")
    print("Only these application A records will switch: " + ", ".join(apps))
    zone = input("Cloudflare Zone ID for " + domain + ": ").strip()
    if not re.fullmatch(r"[a-fA-F0-9]{32}", zone):
        raise SafetyError("Zone ID must be 32 hexadecimal characters")
    token = getpass.getpass("Cloudflare API token (input hidden): ").strip()
    if not token or len(token) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise SafetyError("Invalid API token format")
    local_ip = input("Existing NPM LAN IPv4 (read it from your current OPNsense forward): ").strip()
    address = ipaddress.ip_address(local_ip)
    private_ranges = [ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    if address.version != 4 or not any(address in net for net in private_ranges):
        raise SafetyError("Enter NPM's actual private LAN IPv4, not Oracle or your public home IP")
    cfg = {
        "zone_id": zone, "oracle_ip": oracle_ip, "home_ip": home_ip,
        "health": {"primary_host": health_host, "local_ip": str(address),
                   "path": "/__edge_health", "expected_body": "edge-ok-v1\n", "timeout_seconds": 5},
        "token_file": str(directory / "cf-token"),
        "state_file": str(directory / "state.json") if args.local else "/var/lib/oracle-edge/state.json",
        "interval_seconds": 15, "failures_required": 4, "recovery_seconds": 300,
        "minimum_dwell_seconds": 600, "api_timeout_seconds": 10,
    }
    api = Cloudflare(cfg, token)
    inventory = api.inventory()

    def reference(name):
        selected = [r for r in inventory if r.get("name", "").lower().rstrip(".") == name and r.get("type") == "A"]
        if len(selected) != 1:
            raise SafetyError(f"Expected exactly one existing A record for {name}")
        return {"name": name, "id": selected[0]["id"]}

    cfg["canary"] = reference(health_host)
    cfg["apps"] = [reference(name) for name in apps]
    # Validate the complete schema before saving credentials or the active config.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as candidate:
        json.dump(cfg, candidate)
        candidate.flush()
        cfg = load_config(candidate.name)
    by_id, _ = validate_inventory(cfg, inventory)
    mode = observed_mode(cfg, by_id)
    if mode == "mixed":
        raise SafetyError("Managed records disagree; put them in the same tested mode before setup")
    gid = None if args.local else grp.getgrnam("oracle-edge").gr_gid
    private_write(directory / "cf-token", token + "\n", 0o600)
    private_write(directory / "watchdog.json", json.dumps(cfg, indent=2) + "\n", 0o600 if args.local else 0o640,
                  gid)
    print(f"Local config saved. Observed DNS mode: {mode}. No DNS records were changed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (APIError, SafetyError, OSError, ValueError) as exc:
        print("Setup stopped: " + str(exc), file=sys.stderr)
        sys.exit(1)

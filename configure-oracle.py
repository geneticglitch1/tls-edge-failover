#!/usr/bin/env python3
"""Render a private HAProxy configuration; never installs it or changes a firewall."""
import argparse
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from watchdog import SafetyError, canonical_name, public_v4


def render(domain, home_ip):
    domain = canonical_name(domain)
    home_ip = public_v4(home_ip)
    # canonical_name permits only DNS label characters; dots need regex escaping.
    template = (Path(__file__).resolve().parent / "haproxy.cfg.template").read_text()
    result = template.replace("@@DOMAIN_REGEX@@", domain.replace(".", r"\."))
    result = result.replace("@@HOME_IPV4@@", home_ip)
    if "@@" in result:
        raise SafetyError("Unresolved HAProxy template placeholder")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", help="Domain served at home; its subdomains are also accepted")
    parser.add_argument("--home-ip", help="Home public IPv4 address")
    parser.add_argument("--output", type=Path, help="Default: ignored runtime/haproxy.cfg beside this script")
    args = parser.parse_args(argv)
    domain = args.domain or input("Domain served at home (for example, example.com): ").strip()
    home_ip = args.home_ip or input("Current home public IPv4: ").strip()
    content = render(domain, home_ip)
    path = args.output or Path(__file__).resolve().parent / "runtime" / "haproxy.cfg"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".haproxy-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(f"Saved {path}. No services, firewall rules, or DNS records were changed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (SafetyError, OSError, ValueError) as exc:
        print("Setup stopped: " + str(exc), file=sys.stderr)
        sys.exit(1)

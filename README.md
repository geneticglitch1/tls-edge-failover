# TLS Edge Failover

A small HTTPS relay with automatic DNS failover for services hosted at home.

An Oracle Cloud VM forwards encrypted TCP traffic to your existing Nginx Proxy Manager (NPM). A Python watchdog at home checks both routes and switches selected Cloudflare DNS records when the Oracle route fails. It switches back after sustained recovery.

**Cloudflare terminates TLS whenever its orange-cloud proxy is used.** This project keeps Cloudflare out of the normal application traffic path, but the backup route lets Cloudflare decrypt HTTP. It does not provide encryption that hides HTTP from the Cloudflare proxy.

## Two routes

### Normal: Oracle, DNS only / grey cloud

```mermaid
flowchart LR
    V[Visitor] -->|Encrypted HTTPS| O[Oracle: HAProxy TCP relay]
    O -->|Same TLS session| F[Home: OPNsense WAN 443]
    F --> N[NPM: TLS ends here]
    N --> A[Application]
```

Cloudflare answers DNS with the Oracle address. The visitor then connects directly to Oracle. Oracle forwards TLS bytes without a certificate or private key. It can see network metadata and ordinary TLS SNI, but not the HTTP content under normal verified TLS. See [Cloudflare proxy status](https://developers.cloudflare.com/dns/proxy-status/).

### Backup: Cloudflare, proxied / orange cloud

```mermaid
flowchart LR
    V[Visitor] -->|TLS session 1| C[Cloudflare: TLS ends here]
    C -->|TLS session 2: Full strict| F[Home: OPNsense WAN 443]
    F --> N[NPM: origin TLS ends here]
    N --> A[Application]
```

The A records now contain the home address and have proxying enabled. Oracle is bypassed. Cloudflare can read HTTP requests and responses, including application credentials and cookies. [Cloudflare describes these as two separate connections](https://developers.cloudflare.com/ssl/get-started/).

| Property | Oracle mode | Cloudflare backup |
| --- | --- | --- |
| Managed A record content | Oracle public IPv4 | Home public IPv4 |
| Proxy status | DNS only | Proxied |
| TLS termination | Home NPM | Cloudflare, then NPM on a separate connection |
| Cloudflare WAF / Access in the path | No | Yes, if configured |
| Oracle in the path | Yes | No |

Putting an **orange cloud on the Oracle address** creates a third route: visitor → Cloudflare → Oracle → home. Cloudflare still terminates visitor TLS in that arrangement. The watchdog does not select that mode.

## What it includes

- TLS passthrough with domain/SNI checks and connection limits.
- Three HTTPS checks: direct Oracle, local NPM, and the public Cloudflare backup.
- Public DNS-over-HTTPS for the backup check, so home split DNS cannot silently bypass Cloudflare.
- Failover after four consecutive primary failures, provided local NPM and the backup route work.
- Automatic return after five continuous healthy minutes and a ten-minute minimum stay in backup. Restarts reset these timers conservatively.
- Exact DNS record IDs, conflict checks, API backoff, total network deadlines, a single-process lock, and API readback after changes.
- Hidden token entry, private runtime files, and an optional sandboxed systemd service.
- An optional Ubuntu 24.04 Oracle installer with read-only firewall preflight and timed firewall rollback.

The default profile manages **only the apex and wildcard A records**. It leaves the permanent health record, mail records, and explicit unrelated records alone. Use repeated `--app` options during configuration to manage a smaller list.

## Start here

1. Read [Installation](docs/INSTALL.md) for a new deployment.
2. Already running an earlier version? Use [Updating an existing installation](docs/OPERATIONS.md#updating-an-existing-installation). Keep the existing private configuration.
3. Read [Design](docs/DESIGN.md) for probes, DNS ownership, and failover timing.
4. Read [Security](SECURITY.md) for exactly what is encrypted, exposed, and trusted.
5. Use [Operations](docs/OPERATIONS.md) and [Troubleshooting](docs/TROUBLESHOOTING.md) for logs, recovery, and outage drills.

## Requirements and scope

- Existing working NPM HTTPS hosts behind a home TCP 443 port-forward.
- Publicly trusted certificates on NPM; certificate renewal must work without opening Oracle port 80. DNS-01 is suitable.
- A reserved Oracle public IPv4; the provided installer targets a dedicated Ubuntu 24.04 VM, including ARM64.
- A home Linux/Unix host with Python 3.9+ and network access to NPM, Oracle, Cloudflare's API, and public DNS-over-HTTPS. A maintained Python release is recommended for deployment.
- A Cloudflare zone and a zone-scoped DNS-edit API token.
- A stable home public IPv4 for the documented profile. Home-IP changes require coordinated configuration changes.

This is HTTPS over TCP 443. It does not install a forward proxy, VPN, tunnel, HTTP port 80 redirect, UDP/QUIC relay, or public IPv6 listener. It cannot fix a home Internet outage or migrate existing connections during DNS failover. A static NPM health page does not test every application.

## Development

No pip dependencies are required.

```bash
python3 -m unittest discover -s tests -v
for script in setup-oracle.sh setup-home.sh install-firewall.sh preflight-oracle.sh; do
  bash -n "$script" || break
done
```

Tests mock DNS/API/HTTPS and firewall commands. GitHub Actions also validates a rendered configuration with Ubuntu's HAProxy; CI does not deploy infrastructure. See [Contributing](CONTRIBUTING.md).

## Publishing your copy

This repository contains generic examples. Setup writes installation-specific files to ignored `runtime/` or system directories. **Do not publish runtime folders, tokens, certificates, logs, backups, or filled-in configuration.** Git ignores prevent accidental staging, not deliberate `git add -f` or secret disclosure in issues.

See [Publishing](docs/PUBLISHING.md) for exact GitHub upload steps. Source is licensed under [MIT](LICENSE).

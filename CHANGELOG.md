# Changelog

## 0.1.0 — Initial public source

- Generalized domain, Oracle IP, home IP, and health-host configuration; added a private HAProxy template renderer.
- Preserved existing private watchdog configuration compatibility for upgrades.
- Fixed backup health checks bypassing Cloudflare under home split DNS by using authenticated public DNS-over-HTTPS, with no LAN fallback.
- Kept certificate, exact-body, no-store, Cloudflare-header, and uncached-response checks.
- Added fixed-home-IP mode where the canary is read-only and only configured application A records are updated.
- Supported apex/wildcard record management while leaving explicit unrelated names and mail records alone.
- Preserved total network deadlines, API backoff, readback verification, atomic state, process locking, and conservative recovery timers.
- Moved Oracle firewall conflict detection ahead of package/config changes; refused installed inactive UFW and disabled package removal during installation.
- Retained timed firewall rollback and existing OCI OUTPUT rules.
- Added regression tests, CI, installation/operations guides, diagrams, and an explicit explanation of Cloudflare TLS termination.
- Excluded installation data from source and provided fresh publication instructions.

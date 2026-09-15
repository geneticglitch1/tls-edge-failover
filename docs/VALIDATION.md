# Validation of the initial source

Local validation completed with Python 3.14.7 on macOS:

- **49 automated tests passed**, using mocked network/API calls and isolated fake firewall commands.
- All four Bash scripts passed individual `bash -n` checks.
- The generalized renderer was tested for bounded/escaped SNI matching, rejected injection/invalid addresses, private output permissions, and replacement of existing output.
- Both the default apex/wildcard wizard and a custom selected-app/health-host configuration were tested without remote DNS writes.
- The public-DNS canary, certificate/body/cache requirements, failure/recovery timing, record boundaries, state reconciliation, and total deadlines retained their regression coverage.
- Read-only preflight was tested against clean rules, active UFW, installed inactive UFW, leftover chains, and a native nftables table.

The GitHub Actions workflow is configured to run tests on Python 3.9, 3.12, and 3.14 under Ubuntu 24.04, and to parse a rendered configuration with that distribution's HAProxy. Those GitHub jobs have not run merely because the source was prepared locally.

No live Oracle, Cloudflare, OPNsense, or NPM configuration was changed during repository preparation. HAProxy/systemd deployment and the timed live firewall rollback were not exercised on this macOS machine. Complete the installation checks and an external application outage drill before relying on a deployment.

The publication copy uses generic identifiers and excludes runtime/configuration data, secrets, logs, captures, and previous deployment history. Review future additions and commits before publishing; a static initial scan cannot guarantee later commits stay private.

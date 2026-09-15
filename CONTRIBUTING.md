# Contributing

Use Python 3.9+ on Linux/macOS and Bash for the shell helpers. No Python package installation is needed. Use a maintained Python release for live deployments; compatibility with older Python is not an OS security-support promise.

```bash
python3 -m unittest discover -s tests -v
for script in setup-oracle.sh setup-home.sh install-firewall.sh preflight-oracle.sh; do
  bash -n "$script" || break
done
```

The tests cover route validation, state transitions, API ambiguity/readback, deadlines, fixed-IP DNS ownership, wildcard validation, split-DNS avoidance, configuration rendering, private file permissions, and firewall preflight. Network/API calls and firewall commands are mocked. They neither contact the fixture addresses nor require credentials or root.

If HAProxy is available, render a temporary test configuration and run its syntax validator. The public IP below is only a parser fixture, not a deployment destination:

```bash
python3 configure-oracle.py --domain example.com --home-ip 8.8.8.8
sudo haproxy -c -f runtime/haproxy.cfg
```

Do not start the sample configuration as a real service. GitHub Actions performs this parser check on Ubuntu 24.04. Tests do not replace checking real NPM certificates, Cloudflare settings, OCI networking, or timed firewall recovery during deployment.

Preserve these invariants when contributing:

- No DNS writes without explicit `--apply`.
- No token or origin-secret forwarding to public health endpoints.
- No accepting failed certificates, cached health pages, or local split DNS as a Cloudflare canary success.
- Only configured record identities are eligible for writes.
- No blanket firewall flushes, package removals, or loss of OCI OUTPUT protections.
- No installed deployment values, credentials, logs, or captures in source/history.

The example JSON is deliberately invalid until placeholders are replaced; use the interactive wizard to generate private configuration. Do not fill in the tracked example for a real deployment.

Submit focused changes with relevant tests and a description of the changed behavior. Follow [SECURITY.md](SECURITY.md) when reporting vulnerabilities.

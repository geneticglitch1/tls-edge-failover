# Installation

This guide keeps the existing home WAN 443 → NPM forwarding. It creates a relay on Oracle and runs the DNS watchdog at home. No DNS changes occur merely from running either configuration wizard.

Already deployed? Follow [the update procedure](OPERATIONS.md#updating-an-existing-installation) instead of rerunning the firewall installer.

## 1. Collect the values

| Value | Meaning | Where it is used |
| --- | --- | --- |
| Domain | Your domain managed in Cloudflare; called a **zone** there | DNS record names and TLS SNI |
| Oracle IPv4 | Reserved public IPv4 assigned to your VM | Public DNS, home source allowlist, primary health probe |
| Home IPv4 | Current public WAN IPv4 | Oracle's forwarding destination and Cloudflare backup |
| NPM LAN IPv4 | The address already targeted by your home port-forward | The watchdog's local HTTPS check only; it does not change the forward |
| Administrator CIDR | Your SSH source public IPv4 followed by `/32`, meaning one address | Restricts SSH on Oracle; the installer derives it from the SSH connection |
| Zone ID | Cloudflare's identifier shown on the zone overview page | API configuration |

`example.com` in this guide is a placeholder. Enter your own values when the scripts prompt. Do not put personal values into tracked source files.

Use a reserved Oracle public IP so stop/start operations do not unexpectedly change your allowlist or DNS. The documented configuration assumes a fixed home address; see [IP changes](OPERATIONS.md#home-or-oracle-ip-changes).

## 2. Keep the home forward; add Oracle to its allowed sources

In OPNsense, keep your existing TCP WAN 443 → NPM LAN 443 forward.

1. Create a host alias, for example `oracle_edge`, containing your Oracle public IPv4.
2. Include that alias alongside the existing Cloudflare IP ranges in the **source restriction that actually governs this forward**. You can use a combined alias with your existing Cloudflare aliases plus `oracle_edge`.
3. Apply the change. Keep both Cloudflare and Oracle sources allowed permanently.
4. Check both the NAT rule and its associated WAN pass rule. Adding an unused alias alone grants no access. A source restriction on the NAT rule must also include Oracle so translation occurs.

Do not add another port-forward. Do not expose NPM's administration port 81. If your existing rules use a different layout, inspect them rather than replacing them with a generic rule. Keep the [official Cloudflare address lists](https://www.cloudflare.com/ips/) current. See [OPNsense NAT documentation](https://docs.opnsense.org/manual/nat.html).

## 3. Create one permanent Cloudflare health hostname

Leave your currently working application DNS in its current mode while preparing the other route. For a new deployment that starts through Cloudflare, both managed application A records should contain your home IPv4 and be proxied.

Add this record in Cloudflare DNS, substituting your own domain and home IP:

| Type | Name | Content | Proxy status | TTL |
| --- | --- | --- | --- | --- |
| A | `edge-health` | Home public IPv4 | Proxied / orange | Auto |

The resulting name is `edge-health.example.com`. It stays pointed at home even when applications use Oracle. Do not include it among the switchable records.

Under **SSL/TLS**, use **Full (strict)**. Ensure both the Cloudflare edge certificate and NPM certificate cover all failover hostnames. Avoid any origin rule that sends this health hostname somewhere else or changes its SNI/Host. Existing Worker routes, redirects, or Access policies can also intercept requests.

Full (strict) authenticates and encrypts the Cloudflare-to-home connection; it does not hide HTTP from Cloudflare. [Mode requirements](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/).

## 4. Add the NPM health host

Create a separate **Proxy Host** in NPM:

| Setting | Value |
| --- | --- |
| Domain name | `edge-health.example.com`, using your domain |
| Scheme / forward host / port | `http` / `127.0.0.1` / `9` |
| Access list | Publicly Accessible |
| SSL certificate | Publicly trusted certificate covering this hostname |
| Advanced | Contents of `npm-health-advanced.conf` |

The forwarding address is an unused UI placeholder: the supplied configuration returns the health marker directly and rejects every other path. It must be on this dedicated health host, not your application hosts. Do not add custom locations that override it.

Your existing valid wildcard certificate can cover this single-level health subdomain. A Cloudflare Origin CA-only certificate is unsuitable for this setup because the direct Oracle route must be trusted by ordinary clients. [Origin CA limitations](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/).

In Cloudflare, create a **Cache Rule** matching this expression with Cache eligibility set to **Bypass cache**:

```text
(http.host eq "edge-health.example.com" and http.request.uri.path eq "/__edge_health")
```

Substitute your domain. Ensure this path does not receive a challenge, Access login, or redirect. Scope any exception to this harmless health hostname/path, preserving application protections. The response must be status 200, exactly `edge-ok-v1` followed by a newline, `Cache-Control: no-store`, `CF-Ray`, and `CF-Cache-Status: DYNAMIC` or `BYPASS`.

## 5. Prepare the Oracle VM

Copy this source folder to the VM using your usual SSH/SCP method. Do not copy home credentials or `runtime/` from another machine. On Oracle, in the source folder:

```bash
python3 configure-oracle.py
```

Enter the domain and home public IPv4. This generates ignored `runtime/haproxy.cfg` with private file permissions.

### OCI network rules

In the VM's applicable NSGs/security lists, allow **stateful** IPv4 ingress:

- TCP 443 from `0.0.0.0/0`, because ordinary clients connect directly to Oracle.
- TCP 22 from your administrator public IPv4 `/32`.

Retain the egress needed for home TCP 443, DNS, package updates, and OCI operation. Audit the combined NSGs and security lists: another broad rule can still grant access. This profile does not require ingress on port 80, 3128, or UDP 443. See [OCI security rules](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securityrules.htm).

### Dedicated Ubuntu 24.04 VM only

Have an OCI console recovery method available. Keep your existing SSH session open. The installer expects IPv4 SSH on port 22 and refuses existing UFW/Docker/custom native firewall setups rather than removing their policy.

```bash
sudo bash preflight-oracle.sh
sudo env "SSH_CONNECTION=$SSH_CONNECTION" bash setup-oracle.sh
```

If preflight stops, read [the firewall troubleshooting section](TROUBLESHOOTING.md#oracle-firewall-or-installer-stops). Do not disable a firewall simply to force the installer through.

The installer validates HAProxy's configuration, enables the relay, and stages the host firewall with a **180-second rollback timer**. The host firewall permits administrator SSH and public TCP 443, essential ICMP/DHCP and established traffic, while blocking other new incoming services. It preserves existing OUTPUT rules, including OCI InstanceServices protections. Existing established sessions are intentionally retained.

### Complete the timed firewall verification

Before the timer expires, open a **new** SSH session to Oracle from your administrator address. From the home server or another external terminal, enter the real values and test:

```bash
read -r -p 'Health hostname: ' HEALTH_HOST
read -r -p 'Oracle public IPv4: ' ORACLE_IP
curl --noproxy '*' --fail --show-error --max-time 15 \
  --resolve "$HEALTH_HOST:443:$ORACLE_IP" \
  "https://$HEALTH_HOST/__edge_health"
```

Run those commands in Bash. Require `edge-ok-v1` and a valid certificate. Also test a real NPM application with `--resolve` using its own hostname. Never add `-k` to bypass certificate verification.

After successful tests, run the **exact timer-stop, rollback-status, chain-check, and persistence commands printed by the installer**. Timer names are generated for each run. Verify the rollback service is inactive and both head jumps still exist before saving with `netfilter-persistent save`.

If you miss the deadline, the firewall restores its pre-change rules. Inspect the state before trying again; do not save blindly. The timer rolls back firewall rules, not installed packages or HAProxy configuration.

## 6. Create the Cloudflare API token

Create a custom token with **Zone → DNS → Edit**, scoped to **only the zone being managed**. Record the Zone ID from that zone's overview page. The script requests existing DNS records by that known ID and does not need account administration privileges.

Use a separate token from certificate-renewal/DDNS automation. Enter it into the hidden prompt; do not paste it into a command, tracked file, screenshot, or issue. Cloudflare's token resource scope is the zone; the script's per-record checks narrow its own actions but cannot reduce what a stolen zone token could do. [API token permissions](https://developers.cloudflare.com/fundamentals/api/reference/permissions/).

## 7. Configure and run at home

Copy the source folder to an always-on **home** server. Run from that folder as one consistent user:

```bash
python3 configure-home.py --local
python3 watchdog.py --config "$PWD/runtime/watchdog.json" --check
```

Enter your domain, Oracle IPv4, home IPv4, Zone ID, hidden token, and NPM's existing LAN IPv4. The wizard looks up exact record IDs and saves private local configuration. It does not change DNS or OPNsense.

To switch only selected existing A records, use this in place of the first command (substitute your domain):

```bash
python3 configure-home.py --local \
  --app app.example.com --app status.example.com
```

Quote wildcard arguments, such as `--app '*.example.com'`, so the shell does not expand them. `--health-host` can select a different dedicated proxied health name within the domain.

`--check` requires all three routes to pass. It resolves the Cloudflare canary using authenticated public DNS-over-HTTPS, independently of local split DNS. The home server must reach public `1.1.1.1:443`. Local NPM and Oracle checks use their explicit IPs with the correct TLS hostname.

Once all checks pass, switch to Oracle:

```bash
python3 watchdog.py --config "$PWD/runtime/watchdog.json" \
  --once --mode oracle --apply
```

Verify the managed records now contain the Oracle IP, **DNS only**, TTL 60, and that real applications work from an external network. Explicit DNS records can override wildcard routing.

Start the continuous watchdog:

```bash
umask 077
nohup python3 -u watchdog.py --config "$PWD/runtime/watchdog.json" \
  --run --apply > runtime/watchdog.log 2>&1 &
echo $! > runtime/watchdog.pid
tail -n 50 -F runtime/watchdog.log
```

`Ctrl+C` exits the log viewer only. `nohup` survives terminal closure; it does **not** restart the watchdog after a server reboot or process failure. Use your home server's service supervisor for that, or the systemd option below. Do not run two copies. Without `--apply`, no DNS changes occur.

## 8. Test failover and automatic return

Follow the [outage drill](OPERATIONS.md#outage-drill). Expect a switch after four failing Oracle probes only when the local and public Cloudflare probes are healthy. DNS caches add delay. Recovery is automatic after five continuous healthy minutes and a ten-minute minimum backup dwell; you do not rerun an Oracle script to switch back.

## Optional: systemd on a home Ubuntu 24.04 host

Choose this instead of the plain `nohup` process. Stop any existing local watchdog first. This installer copies the scripts to system paths and prompts for a separate private configuration:

```bash
sudo bash setup-home.sh
sudo python3 -I /usr/local/lib/oracle-edge/watchdog.py \
  --config /etc/oracle-edge/watchdog.json --once --mode oracle --apply
sudo chown -R oracle-edge:oracle-edge /var/lib/oracle-edge
sudo systemctl enable --now oracle-edge-watchdog.service
sudo journalctl -u oracle-edge-watchdog.service -n 50 -f
```

The service runs as an unprivileged account and reads the token through systemd credentials. The installer does not start the writer until you enable it. Keep `/etc/oracle-edge` and `/var/lib/oracle-edge` out of your repository. For service-based updates and manual switches, see [Operations](OPERATIONS.md).

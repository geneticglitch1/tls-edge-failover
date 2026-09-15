# Troubleshooting

## Oracle fails but nothing switches

Look at the entire `health` event. Automatic fallback requires four consecutive failing **primary** checks and successful **local** and **canary** checks in the decision cycle. Also check `startup` contains `apply: true` and inspect `api_hold` or `fatal` events.

An increasing failure counter alone does not authorize a switch to an unproven backup. No companion failover script is needed on Oracle; it only needs a working HAProxy service when that route is meant to be available.

## Canary must traverse Cloudflare with cache bypassed

An HTTP 200 from NPM alone is insufficient. The backup check must actually cross Cloudflare, have `CF-Ray`, and have `CF-Cache-Status: DYNAMIC` or `BYPASS`.

For an investigation on the home Linux server, run these in Bash:

```bash
read -r -p 'Health hostname: ' HEALTH_HOST
getent ahosts "$HEALTH_HOST"
dig @1.1.1.1 "$HEALTH_HOST" A +short
curl --noproxy '*' -sS -D - --max-time 15 \
  -w '\nConnected to: %{remote_ip}\n' \
  "https://$HEALTH_HOST/__edge_health?check=$(date +%s)"
```

If the local answer and curl destination are the NPM LAN IP while public DNS returns Cloudflare addresses, split DNS is bypassing Cloudflare. The DNS record being orange in the dashboard does not override your local resolver.

The corrected watchdog solves this internally: only its canary uses authenticated public DNS-over-HTTPS. It keeps normal local DNS untouched. Update `watchdog.py` using [Operations](OPERATIONS.md#updating-an-existing-installation), stop the old process, run `--check`, then restart it. Plain curl without `--resolve` will still follow your system resolver; that does not mean the corrected watchdog uses it.

If an actual Cloudflare response is returned, inspect the Cache Rule, cache status, WAF/challenge/Access settings, Worker routes, redirects, and origin rules on this dedicated hostname. Do not pin a Cloudflare website IP permanently in `/etc/hosts`; those addresses can change.

## Public canary DNS lookup failed / deadline exceeded

The canary requires outbound TCP 443 to `1.1.1.1`, verified TLS for `cloudflare-dns.com`, and a successful public A answer. Check firewall filtering, intercepting proxies, system CA certificates, and system time. The process bypasses proxy environment variables.

The five-second default is a total budget for the lookup plus the health connection. A persistently slow but otherwise valid route may need a reviewed increase of `health.timeout_seconds` in private config (supported range: 1–15 seconds). Do not disable verification or accept a local DNS fallback.

## Local check fails but primary works

The watchdog belongs **at home**, where it can reach NPM's LAN address. On Oracle, that private IP normally has no route to your home LAN. Confirm `health.local_ip` is NPM's existing address, home routing permits TCP 443, and the NPM certificate covers `health.primary_host`.

From home, force the NPM destination while preserving the hostname:

```bash
read -r -p 'Health hostname: ' HEALTH_HOST
read -r -p 'NPM LAN IPv4: ' NPM_IP
curl --noproxy '*' --fail --show-error --max-time 15 \
  --resolve "$HEALTH_HOST:443:$NPM_IP" \
  "https://$HEALTH_HOST/__edge_health"
```

This is a local diagnostic, not proof that the Cloudflare path works.

## Primary check fails

On Oracle, inspect without changing policy:

```bash
sudo systemctl status haproxy --no-pager
sudo journalctl -u haproxy -n 50 --no-pager
sudo ss -lntp
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
sudo iptables -S
sudo ip6tables -S
sudo nft list tables
```

Check Oracle's applicable OCI network rules, host INPUT rule order, HAProxy's home address, and the home NAT/source allowlist. An ACCEPT below an unconditional REJECT/DROP will not permit new traffic. ICMP ping success does not prove TCP 443 works.

To locate missing traffic, capture the relevant interface and protocol. Oracle HTTPS enters the home **WAN** first, then forwarded traffic reaches LAN/NPM. A LAN-only ICMP capture cannot establish that a WAN TCP 443 request never arrived. Filter for the actual Oracle source and TCP port 443 on WAN, then inspect the translated destination on LAN. This repository does not configure WireGuard.

## Oracle firewall or installer stops

The automatic installer targets a dedicated Ubuntu 24.04 VM. Preflight runs before apt installation, service masking, and replacing configuration. It stops for active firewall managers, installed UFW even if inactive, Docker, recognized leftover UFW/Docker/edge chains, or unexpected native nftables tables.

This avoids package conflicts removing an installed-but-inactive firewall package and discovering leftover chains only after services were changed. Package installation also uses `--no-remove`.

On an existing or partly configured VM:

1. Preserve the working SSH session and establish console recovery access.
2. Inspect the rules/services above and installed firewall packages.
3. Back up both live rulesets privately before any changes:

   ```bash
   sudo sh -c 'umask 077
   iptables-save > /root/edge-before.v4
   ip6tables-save > /root/edge-before.v6'
   ```

4. Determine which existing manager owns policy. Use that manager or a deliberately reviewed migration. Do not flush all tables, delete OCI InstanceServices OUTPUT rules, or remove arbitrary chains/ports.
5. If earlier installation output failed before the firewall helper armed a timer, no rollback timer exists for that attempt. Check actual state rather than assuming a timer is running.

A narrow TCP 443 INPUT fix may restore connectivity on a legacy iptables-managed host, but it does not prove the host's SSH/IPv6 policy is fully hardened. Review the whole policy separately. This guide intentionally does not provide a universal destructive firewall reset.

The timed helper restores pre-change rules after 180 seconds unless you complete the printed verification steps. If the deadline elapsed, inspect the actual head jumps and rollback status before saving. Do not rerun the full package/configuration installer just to repair one rule.

## DNS identity, mixed state, or API errors

- **Replaced record ID / conflicting address record:** inspect the actual names and IDs, including AAAA, CNAME, HTTPS, and SVCB conflicts. Do not delete unrelated records indiscriminately.
- **Mixed startup mode / state disagrees:** stop the writer, inspect DNS and your chosen healthy destination, then use the explicit manual-mode command in [Operations](OPERATIONS.md#manual-switch-or-repair).
- **Cloudflare HTTP 401/403:** verify token validity, zone ID, permission, and zone scope privately.
- **429:** let the controller respect Retry-After/backoff; restarting repeatedly defeats this protection.
- **Another watchdog owns this state file:** stop the existing process and wait for exit. Deleting the lock file while it is held can let two writers run.
- **Canary drift in fixed-IP mode:** restore its intended proxied/home/Auto state or coordinate an actual home-IP change. The fixed-IP writer never silently repairs the permanent canary.

## It has not switched back yet

Keep Oracle healthy and the home watchdog running. A single primary success is not enough: five continuous healthy minutes and ten minutes of backup dwell must both pass. Restarting the watchdog restarts these windows. Check `local` remains healthy, API operations succeed, and no fatal event stopped the process. API readback success still leaves resolver-cache delay.

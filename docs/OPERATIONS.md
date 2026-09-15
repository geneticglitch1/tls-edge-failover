# Operations

Commands below assume a shell in the installed source folder on the **home server**, unless marked Oracle. Keep the same user and private configuration paths used during setup.

## View logs

For the plain Python process:

```bash
tail -n 50 -F runtime/watchdog.log
```

For the optional systemd service:

```bash
sudo journalctl -u oracle-edge-watchdog.service -n 50 -f
```

`Ctrl+C` stops the viewer, not the watchdog. Important JSON events:

| Event | Meaning |
| --- | --- |
| `startup` | Observed DNS mode and current intent; `apply` shows whether writes are enabled |
| `health` | `primary`, `local`, and `canary` status plus consecutive primary failures |
| `hold` | The desired destination was not proven healthy; DNS retained |
| `dry_run` | Proposed action only; no DNS change |
| `dns_verified` | API readback matches the desired DNS state; caches may still use the old route |
| `api_hold` | DNS API error/backoff; inspect authentication, limits, or connectivity |
| `fatal` | Configuration/identity/state conflict; the process stops for inspection |
| `stopped` | Graceful shutdown completed |

Logs may include deployment information. Redact IPs, domains, and paths before sharing them. Never share `cf-token` or unredacted configuration.

## Stop and start the watchdog

For the `nohup` process, first inspect the stored PID:

```bash
ps -p "$(cat runtime/watchdog.pid)" -o pid=,args=
```

Only if it is this watchdog with the expected config, send SIGTERM:

```bash
kill -TERM "$(cat runtime/watchdog.pid)"
tail -n 20 runtime/watchdog.log
```

Wait for `stopped` or confirm that PID has exited before running a manual command. A stale PID file can refer to another process; do not kill it without inspecting. The state lock also prevents a second instance from running against the same state file. Avoid `kill -9` during a DNS write because it can leave a state/DNS conflict to repair.

Restart with:

```bash
umask 077
nohup python3 -u watchdog.py --config "$PWD/runtime/watchdog.json" \
  --run --apply > runtime/watchdog.log 2>&1 &
echo $! > runtime/watchdog.pid
```

This replaces the local log. If you need old logs, rotate/archive them privately before restarting. Configure rotation for a long-running `nohup` deployment; the script itself does not rotate files. For systemd, use `sudo systemctl stop/start oracle-edge-watchdog.service` and journal retention settings instead.

Stopping the watchdog leaves DNS in its last state. It does not shut down HAProxy, NPM, or applications.

## Manual switch or repair

Stop the continuous writer first. To use Oracle:

```bash
python3 watchdog.py --config "$PWD/runtime/watchdog.json" \
  --once --mode oracle --apply
```

To use Cloudflare directly to home:

```bash
python3 watchdog.py --config "$PWD/runtime/watchdog.json" \
  --once --mode cloudflare --apply
```

These bypass recovery timers but require the local and selected route to work. They still enforce record identity checks. `--check` is a separate all-route preflight and cannot be combined with `--apply`.

Mixed records or stored-state disagreement at startup need inspection. Once you have established which route is correct, the explicit one-shot command can reconcile recognized records and replace corrupt/conflicting local state. Do not erase state or change IDs blindly to suppress an error.

For the systemd installation, stop the service and use its installed paths:

```bash
sudo systemctl stop oracle-edge-watchdog.service
sudo python3 -I /usr/local/lib/oracle-edge/watchdog.py \
  --config /etc/oracle-edge/watchdog.json --once --mode cloudflare --apply
sudo chown -R oracle-edge:oracle-edge /var/lib/oracle-edge
sudo systemctl start oracle-edge-watchdog.service
```

Substitute `oracle` to switch back. Run the final start only after the manual command succeeds and the result is understood.

## Outage drill

1. Confirm all three probes pass and the continuous writer logs `apply: true`.
2. Confirm the managed records point at Oracle with DNS only. Verify a real application from outside the LAN; split DNS may keep local browsers on the LAN route regardless of public failover.
3. Watch the home log.
4. **On Oracle**, stop the relay to simulate loss of that route:

   ```bash
   sudo systemctl stop haproxy
   ```

5. Expect `primary: false`, `local: true`, and `canary: true`. After four consecutive primary failures, look for `dns_verified` with `desired: cloudflare`.
6. Confirm both managed A records contain the home IPv4, are proxied, and have Auto TTL. Test an actual application externally. Old DNS answers and existing connections may delay a client moving.
7. **On Oracle**, restore the relay:

   ```bash
   sudo systemctl start haproxy
   sudo systemctl status haproxy --no-pager
   ```

8. The home watchdog should see `primary: true` again. It returns to Oracle after **300 continuous healthy seconds** and **600 seconds in backup**, whichever condition completes later. A watchdog restart restarts both timers. Watch for `dns_verified` with `desired: oracle`.

No failover script runs on Oracle. If the whole VM reboots, HAProxy starts automatically only if its service is enabled and its startup succeeds. The home watchdog must remain running to perform either DNS transition.

If the backup probe fails, the controller deliberately does not switch into that route. Fix the route/probe; do not delete the check to make a drill appear successful. The static health endpoint does not prove the application itself is working.

## Updating an existing installation

The corrected watchdog accepts the prior `runtime/watchdog.json` schema. You do not need to rerun either configuration wizard, recreate DNS records, regenerate credentials, or rerun the Oracle firewall installer merely to update it.

### Plain Python at home

1. Download/extract the new source separately. Review changes and run its local tests.
2. Stop the existing watchdog and wait for its state lock to release.
3. Privately back up the old `watchdog.py` and `runtime/` outside the publication checkout.
4. Copy the new `watchdog.py` into the existing installation folder, preserving `runtime/` and its permissions. Keeping that directory in place also preserves absolute paths stored in configuration.
5. With Oracle running, run:

   ```bash
   python3 watchdog.py --config "$PWD/runtime/watchdog.json" --check
   ```

6. Require all three checks to pass, then restart the continuous process. If a real Oracle outage is ongoing, `--check` will correctly fail its primary probe; verify a backup-target manual operation rather than forcing an all-route success.
7. Repeat the controlled outage drill. This is especially important when installing the public-DNS canary correction.

If you relocate the install folder, update absolute `token_file` and `state_file` paths in the private config. Simply renaming the folder does not rewrite them.

### systemd at home

From the new source folder on the home host:

```bash
sudo systemctl stop oracle-edge-watchdog.service
sudo install -o root -g root -m 644 watchdog.py /usr/local/lib/oracle-edge/watchdog.py
sudo python3 -I /usr/local/lib/oracle-edge/watchdog.py \
  --config /etc/oracle-edge/watchdog.json --check
sudo chown -R oracle-edge:oracle-edge /var/lib/oracle-edge
```

After successful checks:

```bash
sudo systemctl reset-failed oracle-edge-watchdog.service
sudo systemctl start oracle-edge-watchdog.service
```

Back up the old script privately first. The existing `/etc/oracle-edge` credentials/config and `/var/lib/oracle-edge` state stay in place. A service-file change additionally needs review, installation, and `systemctl daemon-reload`; replacing Python alone does not require daemon reload.

## Home or Oracle IP changes

For the fixed-IP profile, a home ISP address change is not automatically handled:

1. Stop the watchdog to prevent competing changes.
2. Update the private home `home_ip`, the permanent proxied canary A record, and any currently active fallback application A records consistently.
3. On Oracle, render a new private configuration with `configure-oracle.py`. Back up the installed configuration. Validate with `sudo haproxy -c -f runtime/haproxy.cfg` before installing it as `/etc/haproxy/haproxy.cfg`, then reload HAProxy.
4. Verify all routes and inspect any state/DNS disagreement. Use an explicit tested manual mode if needed, then restart the watchdog.

For an Oracle public IP change, update the home allowed source, private watchdog `oracle_ip`, relevant OCI access configuration, and active Oracle-mode app records. Add the new allowed source before removing the old one. A reserved public IPv4 avoids most routine address changes.

Do not rerun `setup-oracle.sh` to update only HAProxy's backend; it is an initial host installer with firewall staging.

## Emergency DNS fallback

If the writer cannot run but the Cloudflare route is independently known healthy, stop/disable the writer and edit only its managed application A records in Cloudflare:

- Content: current home public IPv4.
- Proxy: enabled/orange.
- TTL: Auto.

Leave the permanent health record and unrelated records alone. The next normal watchdog start may report a stored-mode conflict because you changed DNS manually; resolve it with the explicit tested `--once --mode cloudflare --apply` operation.

Changing DNS cannot repair home connectivity or instantly move already connected clients. Keep private backups and a known working route available during maintenance.

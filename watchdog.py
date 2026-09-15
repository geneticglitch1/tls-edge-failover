#!/usr/bin/env python3
"""Conservative Cloudflare DNS failover controller. Python 3.9+, Linux/macOS.

No DNS writes occur without --apply. With origin-record mode, OPNsense/DDNS
owns the origin and this controller owns the canary and application A records.
With fixed home_ip mode, only application records are written; canary is read-only.
"""

import argparse
import email.utils
import fcntl
import http.client
import ipaddress
import json
import math
import multiprocessing
import multiprocessing.connection
import os
from pathlib import Path
import random
import re
import secrets
import signal
import socket
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


API_ROOT = "https://api.cloudflare.com/client/v4"
MODES = {"oracle", "cloudflare"}


class SafetyError(Exception):
    """Configuration or observed state requires operator intervention."""


class APIError(Exception):
    def __init__(self, message, retryable=False, retry_after=0):
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = retry_after


class Backoff(APIError):
    pass


def log(event, **fields):
    print(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "event": event, **fields}, sort_keys=True), flush=True)


def canonical_name(value, allow_wildcard=False):
    if not isinstance(value, str):
        raise SafetyError("DNS names must be strings")
    value = value.lower().rstrip(".")
    if allow_wildcard and value.startswith("*."):
        result = "*." + canonical_name(value[2:])
        if len(result) > 253:
            raise SafetyError("DNS name is too long")
        return result
    if len(value) > 253 or "." not in value or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in value.split(".")
    ):
        raise SafetyError("Use fully qualified ASCII hostnames; no wildcards")
    return value


def record_refs(cfg):
    return ([cfg["origin"]] if "origin" in cfg else []) + [cfg["canary"], *cfg["apps"]]


def public_v4(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise SafetyError("Invalid public IPv4 address") from None
    if address.version != 4 or not address.is_global or address.is_multicast:
        raise SafetyError("A globally routable unicast IPv4 address is required")
    return str(address)


def positive_number(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SafetyError(f"{name} must be numeric")
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise SafetyError(f"{name} must be between {minimum} and {maximum}")
    return value


def load_config(path):
    with open(path, encoding="utf-8") as stream:
        cfg = json.load(stream)
    if not isinstance(cfg, dict):
        raise SafetyError("Configuration must be an object")
    allowed = {"zone_id", "oracle_ip", "origin", "home_ip", "canary", "apps", "health",
               "token_file", "origin_secret_file", "state_file", "interval_seconds",
               "failures_required", "recovery_seconds", "minimum_dwell_seconds",
               "api_timeout_seconds"}
    if set(cfg) - allowed:
        raise SafetyError("Unknown configuration fields: " + ", ".join(sorted(set(cfg) - allowed)))
    if not re.fullmatch(r"[a-fA-F0-9]{32}", str(cfg.get("zone_id", ""))):
        raise SafetyError("zone_id must be the exact 32-character Cloudflare ID")
    cfg["oracle_ip"] = public_v4(cfg["oracle_ip"])
    if ("origin" in cfg) == ("home_ip" in cfg):
        raise SafetyError("Configure exactly one of origin (DDNS record) or home_ip (fixed IPv4)")
    if "home_ip" in cfg:
        cfg["home_ip"] = public_v4(cfg["home_ip"])
        if cfg["home_ip"] == cfg["oracle_ip"]:
            raise SafetyError("Home and Oracle IPv4 addresses must differ")
    if not isinstance(cfg.get("apps"), list) or not 1 <= len(cfg["apps"]) <= 100:
        raise SafetyError("Configure between 1 and 100 application records")
    refs = record_refs(cfg)
    for ref in refs:
        if not isinstance(ref, dict) or set(ref) - {"id", "name", "comment"}:
            raise SafetyError("Record references allow id, name, and optional exact comment")
        if not re.fullmatch(r"[a-fA-F0-9]{32}", str(ref.get("id", ""))):
            raise SafetyError("Every DNS record needs its exact 32-character ID")
        ref["name"] = canonical_name(ref["name"], allow_wildcard=any(ref is app for app in cfg["apps"]))
        if "comment" in ref and not isinstance(ref["comment"], str):
            raise SafetyError("Record ownership comment must be a string")
    if len({r["id"] for r in refs}) != len(refs) or len({r["name"] for r in refs}) != len(refs):
        raise SafetyError("Origin, canary, and app IDs and names must all be distinct")
    health = cfg["health"]
    if not isinstance(health, dict) or set(health) - {"primary_host", "local_ip", "path", "expected_body", "timeout_seconds"}:
        raise SafetyError("Unknown or invalid health configuration")
    health["primary_host"] = canonical_name(health["primary_host"])
    if "origin" in cfg and health["primary_host"] == cfg["origin"]["name"]:
        raise SafetyError("The origin DDNS name must not be the primary health hostname")
    local_ip = ipaddress.ip_address(health["local_ip"])
    if local_ip.version != 4 or local_ip.is_multicast or local_ip.is_unspecified:
        raise SafetyError("health.local_ip must be the direct IPv4 address of NPM")
    if str(local_ip) == cfg["oracle_ip"]:
        raise SafetyError("The local NPM probe must not target Oracle")
    health["local_ip"] = str(local_ip)
    path_value = health["path"]
    if not isinstance(path_value, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]*", path_value):
        raise SafetyError("Health path must be an ASCII absolute path without a query")
    marker = health["expected_body"]
    if not isinstance(marker, str) or not 1 <= len(marker.encode()) <= 4096:
        raise SafetyError("expected_body must be 1 to 4096 UTF-8 bytes; newlines are significant")
    defaults = {"interval_seconds": 15, "failures_required": 4, "recovery_seconds": 300,
                "minimum_dwell_seconds": 600, "api_timeout_seconds": 10}
    ranges = {"interval_seconds": (5, 300), "failures_required": (2, 100),
              "recovery_seconds": (60, 86400), "minimum_dwell_seconds": (60, 86400),
              "api_timeout_seconds": (2, 30)}
    for key, default in defaults.items():
        cfg[key] = positive_number(cfg.get(key, default), key, *ranges[key])
    if int(cfg["failures_required"]) != cfg["failures_required"]:
        raise SafetyError("failures_required must be an integer")
    health["timeout_seconds"] = positive_number(health.get("timeout_seconds", 5), "health timeout", 1, 15)
    cfg.setdefault("state_file", "/var/lib/oracle-edge/state.json")
    for key in ("state_file", "token_file", "origin_secret_file"):
        if key in cfg and (not isinstance(cfg[key], str) or not Path(cfg[key]).is_absolute()):
            raise SafetyError(f"{key} must be an absolute path")
    return cfg


def read_secret(cfg, key, credential, required=True):
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    candidate = Path(directory) / credential if directory else None
    if candidate is None or not candidate.is_file():
        candidate = Path(cfg[key]) if cfg.get(key) else None
    if candidate is None:
        if required:
            raise SafetyError(f"Configure {key} or the {credential} systemd credential")
        return None
    value = candidate.read_text(encoding="utf-8").strip()
    if not value or len(value) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise SafetyError(f"Invalid {credential} credential format")
    if credential == "edge_origin_secret" and not re.fullmatch(r"[a-fA-F0-9]{64}", value):
        raise SafetyError("Origin secret must be exactly 64 hexadecimal characters")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def retry_seconds(value):
    if not value:
        return 0
    try:
        return max(0, float(value))
    except ValueError:
        try:
            return max(0, email.utils.parsedate_to_datetime(value).timestamp() - time.time())
        except (ValueError, TypeError, OverflowError):
            return 0


def api_http(job):
    body = None if job["body"] is None else json.dumps(job["body"]).encode()
    request = urllib.request.Request(API_ROOT + job["path"], data=body, method=job["method"],
        headers={"Authorization": "Bearer " + job["token"], "Content-Type": "application/json",
                 "User-Agent": "oracle-edge-watchdog/3"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=job["timeout"]) as response:
            data = response.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024:
            return {"ok": False, "error": "API response exceeded size limit", "retryable": False}
        result = json.loads(data)
        if not isinstance(result, dict) or result.get("success") is not True:
            return {"ok": False, "error": "API reported failure", "retryable": False}
        return {"ok": True, "result": result}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": f"Cloudflare HTTP {exc.code}",
                "retryable": exc.code == 429 or 500 <= exc.code <= 599,
                "retry_after": retry_seconds(exc.headers.get("Retry-After"))}


def public_canary_addresses(host, timeout):
    """Resolve the canary through authenticated public DoH, not LAN split DNS.

    Bootstrap directly to 1.1.1.1; verify TLS for cloudflare-dns.com. No system
    hostname resolution, inherited HTTP proxy, API token, or origin secret is used.
    This runs inside the existing hard-deadline probe worker.
    """
    host = canonical_name(host)
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    query = urllib.parse.urlencode({"name": host, "type": "A"})
    request = ("GET /dns-query?" + query + " HTTP/1.1\r\n"
               "Host: cloudflare-dns.com\r\nAccept: application/dns-json\r\n"
               "Connection: close\r\nUser-Agent: oracle-edge-watchdog/3.1\r\n\r\n")
    with socket.create_connection(("1.1.1.1", 443), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname="cloudflare-dns.com") as tls:
            tls.settimeout(timeout)
            tls.sendall(request.encode("ascii"))
            response = http.client.HTTPResponse(tls)
            response.begin()
            body = response.read(65537)
            if response.status != 200 or len(body) > 65536:
                raise SafetyError("Public DNS HTTPS response failed validation")
    payload = json.loads(body)
    if not isinstance(payload, dict) or payload.get("Status") != 0 or payload.get("TC"):
        raise SafetyError("Public DNS did not return a complete successful answer")
    answers = payload.get("Answer", [])
    if not isinstance(answers, list):
        raise SafetyError("Invalid public DNS answer list")
    addresses = []
    for answer in answers:
        if (isinstance(answer, dict) and answer.get("type") == 1 and
                str(answer.get("name", "")).lower().rstrip(".") == host):
            address = public_v4(answer.get("data", ""))
            if address not in addresses:
                addresses.append(address)
    if not addresses:
        raise SafetyError("Public DNS returned no public IPv4 addresses for the canary")
    return addresses


def probe_http(job):
    target = job["target"]
    if job.get("cloudflare"):
        try:
            target = random.choice(public_canary_addresses(job["host"], job["timeout"]))
        except Exception as exc:
            return {"ok": False, "error": "Public canary DNS lookup failed: " + type(exc).__name__}
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    headers = {"Host": job["host"], "Connection": "close", "Cache-Control": "no-cache, no-store",
               "Pragma": "no-cache", "User-Agent": "oracle-edge-watchdog/3"}
    # The secret is supplied only to the direct LAN probe, never either public route.
    if job.get("origin_secret"):
        headers["X-Edge-Origin-Auth"] = job["origin_secret"]
    path_value = job["path"] + "?_edge_probe=" + secrets.token_hex(16)
    request = "GET " + path_value + " HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
    with socket.create_connection((target, 443), timeout=job["timeout"]) as raw:
        with context.wrap_socket(raw, server_hostname=job["host"]) as tls:
            tls.settimeout(job["timeout"])
            tls.sendall(request.encode("ascii"))
            response = http.client.HTTPResponse(tls)
            response.begin()
            body = response.read(4097)
            if response.status != 200 or body != job["expected"].encode():
                return {"ok": False, "error": "Unexpected HTTP status or health marker"}
            if "no-store" not in response.getheader("Cache-Control", "").lower():
                return {"ok": False, "error": "Health response must include Cache-Control: no-store"}
            if job.get("cloudflare"):
                cache = response.getheader("CF-Cache-Status", "").upper()
                if not response.getheader("CF-Ray") or cache not in {"DYNAMIC", "BYPASS"}:
                    return {"ok": False, "error": "Canary must traverse Cloudflare with cache bypassed"}
    return {"ok": True}


def network_worker(connection, job):
    # A process boundary imposes a real deadline on DNS, TLS, headers, and body.
    try:
        result = api_http(job) if job["kind"] == "api" else probe_http(job)
    except Exception as exc:
        # Do not include remote response bodies, request headers, or credentials.
        result = {"ok": False, "error": type(exc).__name__, "retryable": True}
    try:
        connection.send(result)
    finally:
        connection.close()


def bounded_jobs(jobs):
    context = multiprocessing.get_context("spawn")
    pending, results = {}, {}
    try:
        for name, job in jobs.items():
            receiver, sender = context.Pipe(duplex=False)
            process = context.Process(target=network_worker, args=(sender, job), daemon=True)
            process.start()
            sender.close()
            pending[receiver] = (name, process, time.monotonic() + job["timeout"])
        while pending:
            now = time.monotonic()
            wait_for = max(0, min(deadline for _, _, deadline in pending.values()) - now)
            ready = multiprocessing.connection.wait(list(pending), timeout=min(wait_for, 0.25))
            for receiver in list(pending):
                name, process, deadline = pending[receiver]
                if receiver in ready:
                    try:
                        results[name] = receiver.recv()
                    except (EOFError, OSError):
                        results[name] = {"ok": False, "error": "Network worker exited", "retryable": True}
                elif time.monotonic() >= deadline:
                    results[name] = {"ok": False, "error": "Total network deadline exceeded", "retryable": True}
                else:
                    continue
                receiver.close()
                if process.is_alive():
                    process.terminate()
                process.join(0.25)
                if process.is_alive():
                    process.kill()
                    process.join(0.25)
                del pending[receiver]
        return results
    finally:
        for receiver, (_, process, _) in pending.items():
            receiver.close()
            if process.is_alive():
                process.terminate()
            process.join(0.25)
            if process.is_alive():
                process.kill()
                process.join(0.25)


class Cloudflare:
    def __init__(self, cfg, token):
        self.cfg, self.token = cfg, token
        self.failures = 0
        self.retry_at = 0

    def request(self, method, path, body=None):
        now = time.monotonic()
        if now < self.retry_at:
            raise Backoff("Cloudflare API backoff active", True, self.retry_at - now)
        result = bounded_jobs({"api": {"kind": "api", "token": self.token, "method": method,
            "path": path, "body": body, "timeout": self.cfg["api_timeout_seconds"]}})["api"]
        if result["ok"]:
            self.failures = 0
            self.retry_at = 0
            return result["result"]
        self.failures += 1
        retryable = result.get("retryable", False)
        delay = min(300, 5 * 2 ** min(self.failures - 1, 6)) + random.uniform(0, 2)
        if not retryable:
            delay = 300
        delay = max(delay, result.get("retry_after", 0))
        self.retry_at = time.monotonic() + delay
        raise APIError(result["error"], retryable, delay)

    def inventory(self):
        records = []
        for page in range(1, 101):
            query = urllib.parse.urlencode({"page": page, "per_page": 100})
            result = self.request("GET", f"/zones/{self.cfg['zone_id']}/dns_records?{query}")
            if not isinstance(result.get("result"), list):
                raise SafetyError("Cloudflare returned an invalid DNS inventory")
            records.extend(result["result"])
            info = result.get("result_info", {})
            if not isinstance(info.get("total_pages"), int) or not 0 <= info["total_pages"] <= 100:
                raise SafetyError("DNS inventory pagination is missing or too large")
            if page >= info["total_pages"]:
                return records
        raise SafetyError("DNS inventory exceeded the supported 10,000-record limit")

    def batch_patch(self, patches):
        if patches:
            self.request("POST", f"/zones/{self.cfg['zone_id']}/dns_records/batch", {"patches": patches})


def validate_inventory(cfg, records):
    if not isinstance(records, list) or any(not isinstance(r, dict) for r in records):
        raise SafetyError("Invalid DNS inventory")
    by_id = {}
    for ref in record_refs(cfg):
        named = [r for r in records if str(r.get("name", "")).lower().rstrip(".") == ref["name"]]
        address_records = [r for r in named if r.get("type") in {"A", "AAAA", "CNAME", "HTTPS", "SVCB"}]
        if len(address_records) != 1:
            raise SafetyError(f"{ref['name']}: require exactly one A and no AAAA/CNAME/HTTPS/SVCB records")
        record = address_records[0]
        if record.get("id") != ref["id"] or record.get("type") != "A":
            raise SafetyError(f"{ref['name']}: DNS record type or ID changed")
        if "comment" in ref and record.get("comment") != ref["comment"]:
            raise SafetyError(f"{ref['name']}: ownership comment changed")
        if not isinstance(record.get("proxied"), bool) or not isinstance(record.get("ttl"), int):
            raise SafetyError(f"{ref['name']}: invalid proxy status or TTL")
        public_v4(record.get("content", ""))
        by_id[ref["id"]] = record
    if "origin" in cfg:
        origin = by_id[cfg["origin"]["id"]]
        home_ip = origin["content"]
        if origin["proxied"] or home_ip == cfg["oracle_ip"]:
            raise SafetyError("Origin must be DNS-only home IPv4, different from Oracle")
    else:
        home_ip = cfg["home_ip"]
    canary = by_id[cfg["canary"]["id"]]
    if not canary["proxied"] or canary["content"] == cfg["oracle_ip"]:
        raise SafetyError("Canary must already be proxied to a home address")
    if "home_ip" in cfg and (canary["content"] != home_ip or canary["ttl"] != 1):
        raise SafetyError("Fixed-IP mode requires the read-only canary to match home_ip, proxied, TTL Auto")
    for ref in cfg["apps"]:
        record = by_id[ref["id"]]
        if record["proxied"]:
            if record["content"] == cfg["oracle_ip"]:
                raise SafetyError(f"{ref['name']}: unexpected proxied Oracle address")
        elif record["content"] != cfg["oracle_ip"]:
            raise SafetyError(f"{ref['name']}: unexpected DNS-only target; refusing takeover")
    return by_id, home_ip


def observed_mode(cfg, by_id):
    records = [by_id[ref["id"]] for ref in cfg["apps"]]
    if all(not r["proxied"] and r["content"] == cfg["oracle_ip"] for r in records):
        return "oracle"
    if all(r["proxied"] for r in records) and len({r["content"] for r in records}) == 1:
        return "cloudflare"
    return "mixed"


def patches_for(refs, by_id, content, proxied):
    desired = {"content": content, "proxied": proxied, "ttl": 1 if proxied else 60}
    return [{"id": ref["id"], **desired} for ref in refs
            if any(by_id[ref["id"]].get(key) != value for key, value in desired.items())]


class StateStore:
    def __init__(self, path):
        self.path = Path(path)

    def read(self):
        if not self.path.exists():
            return None
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
            valid = (isinstance(state, dict) and state.get("version") == 1 and
                state.get("mode") in MODES and isinstance(state.get("last_switch"), (int, float)) and
                math.isfinite(state["last_switch"]) and state["last_switch"] >= 0)
            if not valid:
                raise ValueError()
            return state
        except (ValueError, TypeError):
            raise SafetyError("Invalid state file; use explicit --once --mode after investigation") from None

    def write(self, mode, last_switch):
        data = {"version": 1, "mode": mode, "last_switch": last_switch}
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temp_name = tempfile.mkstemp(prefix=".state-", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(data, stream, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)


class HealthWindow:
    def __init__(self, cfg):
        self.cfg = cfg
        self.failures = 0
        self.healthy_since = None
        self.last_sample = None

    def reset(self):
        self.failures = 0
        self.healthy_since = None
        self.last_sample = None

    def sample(self, probes, now):
        if self.last_sample is not None and now - self.last_sample > 2 * self.cfg["interval_seconds"]:
            self.reset()
        self.last_sample = now
        if probes["primary"]["ok"]:
            self.failures = 0
            if self.healthy_since is None:
                self.healthy_since = now
        else:
            self.failures += 1
            self.healthy_since = None

    def target(self, mode, probes, now, dwell_elapsed):
        if mode == "oracle" and self.failures >= self.cfg["failures_required"]:
            if probes["local"]["ok"] and probes["canary"]["ok"]:
                return "cloudflare"
        if mode == "cloudflare" and self.healthy_since is not None:
            if (probes["local"]["ok"] and probes["primary"]["ok"] and
                now - self.healthy_since >= self.cfg["recovery_seconds"] and
                dwell_elapsed >= self.cfg["minimum_dwell_seconds"]):
                return "oracle"
        return mode


def make_probe_jobs(cfg, origin_secret):
    health = cfg["health"]
    shared = {"kind": "probe", "path": health["path"], "expected": health["expected_body"],
              "timeout": health["timeout_seconds"]}
    return {
        "primary": {**shared, "target": cfg["oracle_ip"], "host": health["primary_host"]},
        "local": {**shared, "target": health["local_ip"], "host": health["primary_host"],
                  "origin_secret": origin_secret},
        "canary": {**shared, "target": cfg["canary"]["name"], "host": cfg["canary"]["name"],
                   "cloudflare": True},
    }


class Controller:
    def __init__(self, cfg, api, store, apply=False, manual_mode=None, check=False, origin_secret=None):
        self.cfg, self.api, self.store = cfg, api, store
        self.apply, self.manual_mode, self.check = apply, manual_mode, check
        self.origin_secret = origin_secret
        self.mode = None
        self.last_switch = None
        self.dwell_started = None
        self.window = HealthWindow(cfg)
        self.startup_complete = False

    def inventory(self):
        return validate_inventory(self.cfg, self.api.inventory())

    def initialize(self, by_id, now):
        observed = observed_mode(self.cfg, by_id)
        if observed == "mixed" and self.manual_mode is None:
            raise SafetyError("Mixed DNS at startup: inspect records, then use --once --mode oracle or cloudflare")
        # Manual recovery can replace corrupt state, but only after successful target probes.
        state = None if self.manual_mode else self.store.read()
        if state and state["mode"] != observed:
            raise SafetyError("Stored mode disagrees with DNS: inspect, then use explicit --once --mode")
        self.mode = state["mode"] if state else (observed if observed in MODES else None)
        self.last_switch = state["last_switch"] if state else time.time()
        # Conservative: every restart restarts minimum dwell and continuous health timers.
        self.dwell_started = now
        self.startup_complete = True
        log("startup", observed=observed, desired=self.mode, apply=self.apply)

    def apply_and_verify(self, patches, refs, content, proxied, expected_home):
        self.api.batch_patch(patches)
        by_id, home_ip = self.inventory()
        if home_ip != expected_home:
            raise APIError("Origin changed during update; reconcile with a fresh inventory", True)
        if patches_for(refs, by_id, content, proxied):
            raise APIError("DNS readback does not match desired state; reconciliation pending", True)
        return by_id, home_ip

    def cycle(self):
        by_id, home_ip = self.inventory()
        if not self.startup_complete:
            self.initialize(by_id, time.monotonic())
        canary_refs = [self.cfg["canary"]]
        # In fixed-IP mode the canary is read-only; only application A records are written.
        canary_patches = patches_for(canary_refs, by_id, home_ip, True) if "origin" in self.cfg else []
        if canary_patches:
            log("canary_update_needed", apply=self.apply and not self.check, home_ip=home_ip)
            if self.apply and not self.check:
                by_id, home_ip = self.apply_and_verify(canary_patches, canary_refs, home_ip, True, home_ip)
        probes = bounded_jobs(make_probe_jobs(self.cfg, self.origin_secret))
        now = time.monotonic()
        self.window.sample(probes, now)
        log("health", mode=self.mode, failures=self.window.failures,
            results={key: ({"ok": value["ok"]} if value["ok"] else {"ok": False, "error": value["error"]})
                     for key, value in probes.items()})
        if self.check:
            if canary_patches or not all(result["ok"] for result in probes.values()):
                raise SafetyError("Preflight incomplete: canary drift or a route health probe failed")
            return
        if self.manual_mode:
            target = self.manual_mode
            healthy = probes["local"]["ok"] and probes["primary" if target == "oracle" else "canary"]["ok"]
            if not healthy or (target == "cloudflare" and canary_patches and not self.apply):
                raise SafetyError("Manual target is not proven healthy; DNS left unchanged")
        else:
            target = self.window.target(self.mode, probes, now, now - self.dwell_started)
        # A stale canary cannot justify switching to a newly discovered home address.
        if target == "cloudflare" and canary_patches and not self.apply:
            log("hold", reason="Dry run cannot repair canary drift before validating failover")
            return
        content, proxied = (self.cfg["oracle_ip"], False) if target == "oracle" else (home_ip, True)
        patches = patches_for(self.cfg["apps"], by_id, content, proxied)
        transition = target != self.mode or bool(self.manual_mode)
        target_ready = probes["local"]["ok"] and probes["primary" if target == "oracle" else "canary"]["ok"]
        if (patches or transition) and not target_ready:
            log("hold", reason="Desired target is not proven healthy; preserving observed application DNS")
            return
        if not patches and not transition:
            if self.apply and self.store.read() is None:
                self.store.write(self.mode, self.last_switch)
            return
        if not self.apply:
            log("dry_run", target=target, patches=patches)
            return
        # Persist intent BEFORE a potentially ambiguous API write. A running process
        # keeps reconciling this intent even if the API response or readback is lost.
        if transition:
            switched_at = time.time()
            self.store.write(target, switched_at)
            self.mode, self.last_switch, self.dwell_started = target, switched_at, now
            self.window.reset()
        else:
            self.store.write(self.mode, self.last_switch)
        self.apply_and_verify(patches, self.cfg["apps"], content, proxied, home_ip)
        log("dns_verified", desired=self.mode, records_changed=len(patches),
            note="API readback verified; resolver caches and existing connections may retain the old route")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Absolute path to JSON configuration")
    run_mode = parser.add_mutually_exclusive_group()
    run_mode.add_argument("--check", action="store_true", help="Read-only inventory and all-route health preflight")
    run_mode.add_argument("--once", action="store_true", help="One control cycle (default)")
    run_mode.add_argument("--run", action="store_true", help="Continuous controller")
    parser.add_argument("--apply", action="store_true", help="Explicitly permit configured DNS and state writes")
    parser.add_argument("--mode", choices=sorted(MODES), help="Manual one-shot repair/switch after target probes pass")
    args = parser.parse_args(argv)
    if args.check and args.apply:
        parser.error("--check is read-only and cannot be combined with --apply")
    if args.mode and (args.run or args.check):
        parser.error("--mode is for a one-shot operation; stop the running service first")
    cfg = load_config(args.config)
    token = read_secret(cfg, "token_file", "cf_token")
    origin_secret = read_secret(cfg, "origin_secret_file", "edge_origin_secret", required=False)
    state_path = Path(cfg["state_file"])
    # Lock even check/dry-run invocations to avoid diagnostics racing the writer.
    state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = open(str(state_path) + ".lock", "a", encoding="utf-8")
    os.chmod(lock.name, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SafetyError("Another watchdog owns this state file; stop its service before manual commands") from None
    controller = Controller(cfg, Cloudflare(cfg, token), StateStore(state_path), args.apply,
                            args.mode, args.check, origin_secret)
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    next_cycle = time.monotonic()
    while not stopping:
        try:
            controller.cycle()
        except APIError as exc:
            controller.window.reset()
            log("api_hold", reason=str(exc), retry_seconds=round(exc.retry_after, 1))
            if not args.run:
                return 1
        except SafetyError:
            # Invalid identities, conflicting state, or unexpected DNS is not an outage.
            # Exit and let the operator inspect it instead of overwriting unrelated data.
            raise
        if not args.run:
            return 0
        next_cycle += cfg["interval_seconds"]
        now = time.monotonic()
        if next_cycle <= now:
            next_cycle = now + cfg["interval_seconds"]
        while not stopping and time.monotonic() < next_cycle:
            time.sleep(min(0.25, max(0, next_cycle - time.monotonic())))
    log("stopped")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (SafetyError, KeyError, ValueError, OSError) as exc:
        # Configuration paths are safe to show; credentials and API bodies are never logged.
        log("fatal", reason=str(exc))
        sys.exit(2)

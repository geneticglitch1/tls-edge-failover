#!/usr/bin/env python3
"""Controller tests; all Cloudflare and route operations mocked.

Public resolver IPs are validation fixtures only. No fixture address is contacted.
Names and record IDs are synthetic, unrelated to a real deployment.
"""

import copy
import importlib.util
import io
import json
import multiprocessing
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import watchdog as w


def config():
    return {
        "zone_id": "f" * 32, "oracle_ip": "8.8.8.8",
        "origin": {"id": "1" * 32, "name": "origin.example.com"},
        "canary": {"id": "2" * 32, "name": "standby-health.example.com"},
        "apps": [{"id": "3" * 32, "name": "a.example.com"}, {"id": "4" * 32, "name": "b.example.com"}],
        "health": {"primary_host": "health.example.com", "local_ip": "192.168.1.20",
                   "path": "/edge-health", "expected_body": "edge-ok\n", "timeout_seconds": 5},
        "interval_seconds": 15, "failures_required": 4, "recovery_seconds": 300,
        "minimum_dwell_seconds": 600, "api_timeout_seconds": 10,
    }


def records(cfg):
    return [
        {**cfg["origin"], "type": "A", "content": "1.1.1.1", "proxied": False, "ttl": 60},
        {**cfg["canary"], "type": "A", "content": "1.1.1.1", "proxied": True, "ttl": 1},
        *[{**ref, "type": "A", "content": cfg["oracle_ip"], "proxied": False, "ttl": 60} for ref in cfg["apps"]],
    ]


def probes(primary=True, local=True, canary=True):
    return {name: {"ok": good, "error": "simulated failure"} for name, good in
            {"primary": primary, "local": local, "canary": canary}.items()}


class FakeAPI:
    def __init__(self, data):
        self.data = copy.deepcopy(data)
        self.writes = []
        self.fail_partial_once = False

    def inventory(self):
        return copy.deepcopy(self.data)

    def batch_patch(self, patches):
        self.writes.append(copy.deepcopy(patches))
        for index, patch in enumerate(patches):
            next(r for r in self.data if r["id"] == patch["id"]).update(patch)
            if index == 0 and self.fail_partial_once:
                self.fail_partial_once = False
                raise w.APIError("Simulated ambiguous write", True)


class MemoryStore:
    def __init__(self, state=None):
        self.state = state
        self.writes = []

    def read(self):
        return self.state

    def write(self, mode, last_switch):
        self.state = {"version": 1, "mode": mode, "last_switch": last_switch}
        self.writes.append(copy.deepcopy(self.state))


def slow_worker(connection, job):
    time.sleep(30)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config()
        self.data = records(self.cfg)

    def test_reject_aaaa_at_managed_name(self):
        self.data.append({"id": "5" * 32, "name": "a.example.com", "type": "AAAA", "content": "2606:4700::1111"})
        with self.assertRaises(w.SafetyError):
            w.validate_inventory(self.cfg, self.data)

    def test_reject_replaced_record_id(self):
        self.data[-1]["id"] = "5" * 32
        with self.assertRaises(w.SafetyError):
            w.validate_inventory(self.cfg, self.data)

    def test_reject_origin_proxy_or_oracle_address(self):
        for field, value in [("proxied", True), ("content", "8.8.8.8"), ("content", "192.168.1.1")]:
            with self.subTest(field=field, value=value):
                data = copy.deepcopy(self.data)
                data[0][field] = value
                with self.assertRaises(w.SafetyError):
                    w.validate_inventory(self.cfg, data)

    def test_old_global_proxied_home_address_is_allowed_for_ddns_reconciliation(self):
        for item in self.data[2:]:
            item.update(content="9.9.9.9", proxied=True, ttl=1)
        by_id, home = w.validate_inventory(self.cfg, self.data)
        self.assertEqual(w.observed_mode(self.cfg, by_id), "cloudflare")
        self.assertEqual(len(w.patches_for(self.cfg["apps"], by_id, home, True)), 2)

    def test_ttl_is_part_of_noop_comparison(self):
        by_id, _ = w.validate_inventory(self.cfg, self.data)
        self.assertEqual(w.patches_for(self.cfg["apps"], by_id, "8.8.8.8", False), [])
        by_id["3" * 32]["ttl"] = 300
        self.assertEqual(len(w.patches_for(self.cfg["apps"], by_id, "8.8.8.8", False)), 1)

    def test_origin_secret_sent_to_local_probe_only(self):
        jobs = w.make_probe_jobs(self.cfg, "a" * 64)
        self.assertEqual(jobs["local"]["origin_secret"], "a" * 64)
        self.assertNotIn("origin_secret", jobs["primary"])
        self.assertNotIn("origin_secret", jobs["canary"])


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config()

    def test_failover_requires_four_consecutive_primary_failures_and_both_candidates(self):
        window = w.HealthWindow(self.cfg)
        for now in [0, 15, 30]:
            window.sample(probes(primary=False), now)
            self.assertEqual(window.target("oracle", probes(primary=False), now, 0), "oracle")
        window.sample(probes(primary=False), 45)
        self.assertEqual(window.target("oracle", probes(primary=False), 45, 0), "cloudflare")
        self.assertEqual(window.target("oracle", probes(primary=False, local=False), 45, 0), "oracle")
        self.assertEqual(window.target("oracle", probes(primary=False, canary=False), 45, 0), "oracle")

    def test_recovery_requires_true_elapsed_300_seconds_and_dwell_600(self):
        window = w.HealthWindow(self.cfg)
        for now in range(0, 301, 15):
            window.sample(probes(), now)
        self.assertEqual(window.target("cloudflare", probes(), 299, 600), "cloudflare")
        self.assertEqual(window.target("cloudflare", probes(), 300, 599), "cloudflare")
        self.assertEqual(window.target("cloudflare", probes(), 300, 600), "oracle")

    def test_sample_gap_resets_continuity(self):
        window = w.HealthWindow(self.cfg)
        window.sample(probes(), 0)
        window.sample(probes(), 31)
        self.assertEqual(window.healthy_since, 31)

    def test_success_resets_failure_streak(self):
        window = w.HealthWindow(self.cfg)
        window.sample(probes(primary=False), 0)
        window.sample(probes(), 15)
        window.sample(probes(primary=False), 30)
        self.assertEqual(window.failures, 1)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config()
        self.api = FakeAPI(records(self.cfg))
        self.store = MemoryStore()
        self.logger = mock.patch.object(w, "log")
        self.logger.start()
        self.addCleanup(self.logger.stop)

    def controller(self, **kwargs):
        return w.Controller(self.cfg, self.api, self.store, **kwargs)

    def test_default_dry_run_has_no_remote_or_persistent_state_writes(self):
        self.api.data[1]["content"] = "9.9.9.9"
        ctl = self.controller()
        with mock.patch.object(w, "bounded_jobs", return_value=probes()):
            ctl.cycle()
        self.assertEqual(self.api.writes, [])
        self.assertEqual(self.store.writes, [])

    def test_canary_refreshed_in_oracle_mode_without_touching_origin(self):
        self.api.data[1]["content"] = "9.9.9.9"
        ctl = self.controller(apply=True)
        with mock.patch.object(w, "bounded_jobs", return_value=probes()):
            ctl.cycle()
        patched = [p for batch in self.api.writes for p in batch]
        self.assertEqual([p["id"] for p in patched], ["2" * 32])
        self.assertEqual(patched[0]["content"], "1.1.1.1")

    def test_mixed_startup_refuses_every_write(self):
        self.api.data[2].update(content="1.1.1.1", proxied=True, ttl=1)
        self.api.data[1]["content"] = "9.9.9.9"
        with self.assertRaises(w.SafetyError):
            self.controller(apply=True).cycle()
        self.assertEqual(self.api.writes, [])
        self.assertEqual(self.store.writes, [])

    def test_explicit_manual_mode_repairs_mixed_records_after_healthy_target(self):
        self.api.data[2].update(content="1.1.1.1", proxied=True, ttl=1)
        ctl = self.controller(apply=True, manual_mode="cloudflare")
        with mock.patch.object(w, "bounded_jobs", return_value=probes(primary=False)):
            ctl.cycle()
        self.assertEqual(ctl.mode, "cloudflare")
        self.assertTrue(all(r["proxied"] for r in self.api.data[2:]))

    def test_manual_mode_rejects_unhealthy_target(self):
        ctl = self.controller(apply=True, manual_mode="cloudflare")
        with mock.patch.object(w, "bounded_jobs", return_value=probes(canary=False)):
            with self.assertRaises(w.SafetyError):
                ctl.cycle()
        self.assertEqual(self.api.writes, [])
        self.assertEqual(self.store.writes, [])

    def test_ambiguous_partial_write_keeps_intent_and_repairs_after_primary_recovers(self):
        ctl = self.controller(apply=True)
        with mock.patch.object(w, "bounded_jobs", return_value=probes(primary=False)):
            for _ in range(3):
                ctl.cycle()
            self.api.fail_partial_once = True
            with self.assertRaises(w.APIError):
                ctl.cycle()
        self.assertEqual(ctl.mode, "cloudflare")
        self.assertEqual(self.store.state["mode"], "cloudflare")
        self.assertTrue(self.api.data[2]["proxied"])
        self.assertFalse(self.api.data[3]["proxied"])
        with mock.patch.object(w, "bounded_jobs", return_value=probes()):
            ctl.cycle()
        self.assertTrue(all(r["proxied"] for r in self.api.data[2:]))

    def test_readonly_check_makes_no_writes(self):
        ctl = self.controller(check=True)
        with mock.patch.object(w, "bounded_jobs", return_value=probes()):
            ctl.cycle()
        self.assertEqual(self.api.writes, [])
        self.assertEqual(self.store.writes, [])

    def test_runtime_drift_reconciled_even_without_mode_transition(self):
        ctl = self.controller(apply=True)
        with mock.patch.object(w, "bounded_jobs", return_value=probes()):
            ctl.cycle()
            self.api.data[2].update(content="1.1.1.1", proxied=True, ttl=1)
            ctl.cycle()
        self.assertFalse(self.api.data[2]["proxied"])
        self.assertEqual(self.api.data[2]["content"], "8.8.8.8")

    def test_runtime_drift_not_written_to_unhealthy_target(self):
        ctl = self.controller(apply=True)
        with mock.patch.object(w, "bounded_jobs", return_value=probes()):
            ctl.cycle()
        self.api.data[2].update(content="1.1.1.1", proxied=True, ttl=1)
        with mock.patch.object(w, "bounded_jobs", return_value=probes(primary=False)):
            ctl.cycle()
        self.assertTrue(self.api.data[2]["proxied"])


class PersistenceAndNetworkTests(unittest.TestCase):
    def test_atomic_state_roundtrip_and_private_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            store = w.StateStore(path)
            store.write("cloudflare", 123)
            self.assertEqual(store.read(), {"version": 1, "mode": "cloudflare", "last_switch": 123})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(list(Path(directory).iterdir())), 1)

    def test_corrupt_state_is_not_silently_discarded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text('{"bad": true}')
            with self.assertRaises(w.SafetyError):
                w.StateStore(path).read()

    def test_rate_limit_retry_after_prevents_another_request(self):
        api = w.Cloudflare(config(), "secret-never-logged")
        response = {"api": {"ok": False, "error": "Cloudflare HTTP 429", "retryable": True, "retry_after": 120}}
        with mock.patch.object(w, "bounded_jobs", return_value=response) as network:
            with mock.patch.object(w.time, "monotonic", return_value=10):
                with self.assertRaises(w.APIError):
                    api.request("GET", "/test")
            with mock.patch.object(w.time, "monotonic", return_value=20):
                with self.assertRaises(w.Backoff):
                    api.request("GET", "/test")
            self.assertEqual(network.call_count, 1)
        self.assertGreaterEqual(api.retry_at, 130)

    def test_real_worker_deadline_terminates_stalled_process(self):
        start = time.monotonic()
        with mock.patch.object(w, "network_worker", slow_worker):
            result = w.bounded_jobs({"hung": {"timeout": 0.2}})
        self.assertFalse(result["hung"]["ok"])
        self.assertIn("deadline", result["hung"]["error"])
        self.assertLess(time.monotonic() - start, 3)
        self.assertEqual(multiprocessing.active_children(), [])


class HTTPHealthTests(unittest.TestCase):
    def probe(self, *, status=200, body=b"edge-ok\n", headers=None, cloudflare=False):
        if headers is None:
            headers = {"Cache-Control": "no-store", "CF-Ray": "test-ray", "CF-Cache-Status": "DYNAMIC"}
        response = mock.MagicMock()
        response.status = status
        response.read.return_value = body
        response.getheader.side_effect = lambda name, default=None: headers.get(name, default)
        job = w.make_probe_jobs(config(), None)["canary" if cloudflare else "primary"]
        with mock.patch.object(w.socket, "create_connection"), \
             mock.patch.object(w.ssl, "create_default_context"), \
             mock.patch.object(w, "public_canary_addresses", return_value=["1.0.0.1"]), \
             mock.patch.object(w.http.client, "HTTPResponse", return_value=response):
            return w.probe_http(job)

    def test_rejects_redirect_challenge_and_wrong_body(self):
        for status, body in [(301, b"edge-ok\n"), (403, b"challenge"), (200, b"wrong"), (200, b"edge-ok")]:
            with self.subTest(status=status, body=body):
                self.assertFalse(self.probe(status=status, body=body)["ok"])

    def test_requires_no_store_from_origin(self):
        self.assertFalse(self.probe(headers={})["ok"])

    def test_canary_rejects_cached_or_non_cloudflare_response(self):
        for headers in [
            {"Cache-Control": "no-store", "CF-Ray": "x", "CF-Cache-Status": "HIT"},
            {"Cache-Control": "no-store", "CF-Cache-Status": "BYPASS"},
            {"Cache-Control": "no-store", "CF-Ray": "x"},
        ]:
            with self.subTest(headers=headers):
                self.assertFalse(self.probe(headers=headers, cloudflare=True)["ok"])

    def test_valid_uncached_canary_accepted(self):
        self.assertTrue(self.probe(cloudflare=True)["ok"])

    def test_certificate_verification_error_is_not_accepted(self):
        context = mock.MagicMock()
        context.wrap_socket.side_effect = w.ssl.SSLCertVerificationError("simulated certificate failure")
        with mock.patch.object(w.socket, "create_connection"), \
             mock.patch.object(w.ssl, "create_default_context", return_value=context):
            with self.assertRaises(w.ssl.SSLCertVerificationError):
                w.probe_http(w.make_probe_jobs(config(), None)["primary"])

    def test_canary_connects_to_public_result_with_original_sni_and_host(self):
        response = mock.MagicMock(status=200)
        response.read.return_value = b"edge-ok\n"
        headers = {"Cache-Control": "no-store", "CF-Ray": "x", "CF-Cache-Status": "DYNAMIC"}
        response.getheader.side_effect = lambda name, default=None: headers.get(name, default)
        context = mock.MagicMock()
        job = w.make_probe_jobs(config(), None)["canary"]
        with mock.patch.object(w, "public_canary_addresses", return_value=["1.0.0.1"]) as resolver, \
             mock.patch.object(w.socket, "create_connection") as connect, \
             mock.patch.object(w.ssl, "create_default_context", return_value=context), \
             mock.patch.object(w.http.client, "HTTPResponse", return_value=response):
            self.assertTrue(w.probe_http(job)["ok"])
        connect.assert_called_once_with(("1.0.0.1", 443), timeout=5)
        resolver.assert_called_once_with(job["host"], 5)
        self.assertEqual(context.wrap_socket.call_args.kwargs["server_hostname"], job["host"])
        request = context.wrap_socket.return_value.__enter__.return_value.sendall.call_args.args[0]
        self.assertIn(("Host: " + job["host"] + "\r\n").encode(), request)

    def test_public_dns_failure_never_falls_back_to_lan_resolution(self):
        with mock.patch.object(w, "public_canary_addresses", side_effect=OSError), \
             mock.patch.object(w.socket, "create_connection") as connect:
            result = w.probe_http(w.make_probe_jobs(config(), None)["canary"])
        self.assertFalse(result["ok"])
        connect.assert_not_called()


class PublicDNSTests(unittest.TestCase):
    def resolve(self, payload):
        response = mock.MagicMock(status=200)
        response.read.return_value = json.dumps(payload).encode()
        with mock.patch.object(w.socket, "create_connection") as connect, \
             mock.patch.object(w.ssl, "create_default_context") as context, \
             mock.patch.object(w.http.client, "HTTPResponse", return_value=response):
            result = w.public_canary_addresses("edge-health.example.com", 5)
        connect.assert_called_once_with(("1.1.1.1", 443), timeout=5)
        self.assertEqual(context.return_value.wrap_socket.call_args.kwargs["server_hostname"], "cloudflare-dns.com")
        return result

    def test_bootstrapped_public_resolver_returns_addresses_for_exact_name(self):
        self.assertEqual(self.resolve({"Status": 0, "Answer": [
            {"name": "edge-health.example.com.", "type": 1, "data": "1.0.0.1"},
            {"name": "unrelated.example.com", "type": 1, "data": "8.8.8.8"}
        ]}), ["1.0.0.1"])

    def test_private_or_failed_dns_answers_rejected(self):
        for payload in [
            {"Status": 3},
            {"Status": 0, "TC": True},
            {"Status": 0, "Answer": []},
            {"Status": 0, "Answer": [{"name": "edge-health.example.com", "type": 1, "data": "192.168.50.10"}]},
        ]:
            with self.subTest(payload=payload), self.assertRaises(w.SafetyError):
                self.resolve(payload)


class WildcardFixedIPTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config()
        del self.cfg["origin"]
        self.cfg["home_ip"] = "1.1.1.1"
        self.cfg["oracle_ip"] = "8.8.8.8"
        self.cfg["canary"]["name"] = "edge-health.example.com"
        self.cfg["health"]["primary_host"] = self.cfg["canary"]["name"]
        self.cfg["apps"][0]["name"] = "*.example.com"
        self.cfg["apps"][1]["name"] = "example.com"
        self.data = [
            {**self.cfg["canary"], "type": "A", "content": self.cfg["home_ip"], "proxied": True, "ttl": 1},
            *[{**ref, "type": "A", "content": self.cfg["oracle_ip"], "proxied": False, "ttl": 60}
              for ref in self.cfg["apps"]],
            {"id": "a" * 32, "name": "example.com", "type": "MX", "content": "route3.mx.cloudflare.net"},
            {"id": "b" * 32, "name": "example.com", "type": "TXT", "content": "v=spf1 include:_spf.mx.cloudflare.net ~all"},
            {"id": "c" * 32, "name": "test.example.com", "type": "CNAME", "content": "external.example.net"},
            {"id": "d" * 32, "name": "worker.example.com", "type": "Worker", "content": "example-worker"},
        ]

    def load(self, cfg):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(cfg))
            return w.load_config(path)

    def test_config_accepts_wildcard_apps_and_same_health_host_for_forced_primary(self):
        cfg = self.load(self.cfg)
        self.assertEqual(cfg["apps"][0]["name"], "*.example.com")
        self.assertEqual(cfg["health"]["primary_host"], cfg["canary"]["name"])

    def test_wildcards_forbidden_in_canary_and_health_hostname(self):
        for location in ("canary", "health"):
            cfg = copy.deepcopy(self.cfg)
            cfg[location]["name" if location == "canary" else "primary_host"] = "*.example.com"
            with self.subTest(location=location), self.assertRaises(w.SafetyError):
                self.load(cfg)

    def test_embedded_and_multiple_wildcards_rejected(self):
        for value in ["app*.example.com", "*.*.example.com", "example.*"]:
            with self.subTest(value=value), self.assertRaises(w.SafetyError):
                w.canonical_name(value, allow_wildcard=True)

    def test_fixed_canary_drift_stops_without_writes(self):
        self.data[0]["content"] = "9.9.9.9"
        api = FakeAPI(self.data)
        with self.assertRaises(w.SafetyError):
            w.Controller(self.cfg, api, MemoryStore(), apply=True).cycle()
        self.assertEqual(api.writes, [])

    def test_only_apex_and_wildcard_written_mail_worker_and_canary_untouched(self):
        api = FakeAPI(self.data)
        ctl = w.Controller(self.cfg, api, MemoryStore(), apply=True, manual_mode="cloudflare")
        before = copy.deepcopy(api.data)
        with mock.patch.object(w, "bounded_jobs", return_value=probes()), mock.patch.object(w, "log"):
            ctl.cycle()
        self.assertEqual({patch["id"] for batch in api.writes for patch in batch}, {"3" * 32, "4" * 32})
        self.assertEqual(api.data[0], before[0])
        self.assertEqual(api.data[3:], before[3:])
        self.assertTrue(all(item["content"] == self.cfg["home_ip"] and item["proxied"] for item in api.data[1:3]))

    def test_cannot_configure_both_fixed_ip_and_ddns_origin(self):
        self.cfg["origin"] = {"id": "1" * 32, "name": "origin.example.com"}
        with self.assertRaises(w.SafetyError):
            self.load(self.cfg)

    def test_local_configuration_needs_no_root_and_never_writes_dns(self):
        spec = importlib.util.spec_from_file_location("configure_home", ROOT / "configure-home.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        api = FakeAPI(self.data)
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with mock.patch.object(module, "__file__", str(Path(directory) / "configure-home.py")), \
                 mock.patch.object(module.sys, "argv", ["configure-home.py", "--local"]), \
                 mock.patch.object(module.os, "geteuid", return_value=1000), \
                 mock.patch("builtins.input", side_effect=["example.com", "8.8.8.8", "1.1.1.1", "f" * 32, "192.168.20.10"]), \
                 mock.patch.object(module.getpass, "getpass", return_value="private-test-token"), \
                 mock.patch.object(module, "Cloudflare", return_value=api), \
                 mock.patch.object(module.sys, "stdout", output):
                self.assertEqual(module.main(), 0)
            runtime = Path(directory) / "runtime"
            cfg = json.loads((runtime / "watchdog.json").read_text())
            self.assertEqual(cfg["home_ip"], "1.1.1.1")
            self.assertEqual({ref["name"] for ref in cfg["apps"]}, {"*.example.com", "example.com"})
            self.assertEqual(cfg["state_file"], str((runtime / "state.json").resolve()))
            self.assertEqual((runtime / "cf-token").stat().st_mode & 0o777, 0o600)
            self.assertEqual((runtime / "watchdog.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual(runtime.stat().st_mode & 0o777, 0o700)
            self.assertNotIn("private-test-token", output.getvalue())
            self.assertEqual(api.writes, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

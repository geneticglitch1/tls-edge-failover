"""Setup tests use temporary files and isolated mock commands, never a real firewall."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import watchdog as w


def module_from(filename, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OracleRendererTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.renderer = module_from("configure-oracle.py", "configure_oracle")

    def test_sni_domain_is_escaped_and_bounded(self):
        # Public resolver IP is only a validation fixture; no socket is opened.
        result = self.renderer.render("Example.COM.", "8.8.8.8")
        expression = next(line.split()[-1] for line in result.splitlines() if "acl allowed_sni" in line)
        for good in ("example.com", "app.example.com", "a.b.example.com"):
            self.assertIsNotNone(re.fullmatch(expression, good))
        for bad in ("exampleXcom", "example.com.attacker.test", "other.test", "notexample.com"):
            self.assertIsNone(re.fullmatch(expression, bad))
        self.assertIn("server home 8.8.8.8:443", result)
        self.assertNotIn("@@", result)
        executable = "\n".join(line for line in result.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotRegex(executable, r"\b(?:ssl|crt|send-proxy)\b")

    def test_injection_and_invalid_destinations_rejected(self):
        for domain, address in (("example.com\nbind :80", "8.8.8.8"),
                                ("*.example.com", "8.8.8.8"),
                                ("example.com", "127.0.0.1"),
                                ("example.com", "203.0.113.10"),
                                ("example.com", "8.8.8.8:443")):
            with self.subTest(domain=domain, address=address), self.assertRaises(w.SafetyError):
                self.renderer.render(domain, address)

    def test_rendered_file_is_private_and_existing_file_replaced_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "private" / "haproxy.cfg"
            with contextlib.redirect_stdout(io.StringIO()):
                self.renderer.main(["--domain", "example.com", "--home-ip", "8.8.8.8", "--output", str(destination)])
                self.renderer.main(["--domain", "example.net", "--home-ip", "1.1.1.1", "--output", str(destination)])
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            self.assertEqual(destination.parent.stat().st_mode & 0o777, 0o700)
            self.assertIn(r"example\.net", destination.read_text())
            self.assertEqual([path.name for path in destination.parent.iterdir()], ["haproxy.cfg"])


class HomeWizardTests(unittest.TestCase):
    def setUp(self):
        self.wizard = module_from("configure-home.py", "configure_home_general")

    def test_selected_apps_and_custom_canary_generate_only_requested_references(self):
        records = [
            {"id": "1" * 32, "type": "A", "name": "check.example.net", "content": "1.1.1.1", "proxied": True, "ttl": 1},
            {"id": "2" * 32, "type": "A", "name": "app.example.net", "content": "8.8.8.8", "proxied": False, "ttl": 60},
            {"id": "3" * 32, "type": "A", "name": "example.net", "content": "8.8.8.8", "proxied": False, "ttl": 60},
        ]
        api = mock.Mock()
        api.inventory.return_value = records
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(self.wizard, "__file__", str(Path(directory) / "configure-home.py")), \
             mock.patch.object(sys, "argv", ["configure-home.py", "--local", "--health-host", "check.example.net", "--app", "app.example.net"]), \
             mock.patch("builtins.input", side_effect=["example.net", "8.8.8.8", "1.1.1.1", "f" * 32, "10.50.0.10"]), \
             mock.patch.object(self.wizard.getpass, "getpass", return_value="fixture-token"), \
             mock.patch.object(self.wizard, "Cloudflare", return_value=api), \
             contextlib.redirect_stdout(io.StringIO()):
            self.wizard.main()
            cfg = json.loads((Path(directory) / "runtime/watchdog.json").read_text())
        self.assertEqual(cfg["canary"]["name"], "check.example.net")
        self.assertEqual(cfg["health"]["primary_host"], "check.example.net")
        self.assertEqual(cfg["apps"], [{"id": "2" * 32, "name": "app.example.net"}])
        self.assertEqual(api.mock_calls, [mock.call.inventory()])

    def test_outside_domain_is_rejected_before_token_or_api_access(self):
        for option in ("--app", "--health-host"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as directory, \
                 mock.patch.object(self.wizard, "__file__", str(Path(directory) / "configure-home.py")), \
                 mock.patch.object(sys, "argv", ["configure-home.py", "--local", option, "attacker.test"]), \
                 mock.patch("builtins.input", side_effect=["example.net", "8.8.8.8", "1.1.1.1"]), \
                 mock.patch.object(self.wizard.getpass, "getpass") as token, \
                 mock.patch.object(self.wizard, "Cloudflare") as api:
                with self.assertRaises(w.SafetyError):
                    self.wizard.main()
                token.assert_not_called()
                api.assert_not_called()
                self.assertFalse((Path(directory) / "runtime/cf-token").exists())


class FirewallPreflightTests(unittest.TestCase):
    def run_profile(self, profile):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)
            (binary / "python3").symlink_to(sys.executable)
            dispatcher = """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
profile = os.environ['PREFLIGHT_PROFILE']
with open(os.environ['PREFLIGHT_CALLS'], 'a') as stream:
    stream.write(name + ' ' + ' '.join(sys.argv[1:]) + '\\n')
if name == 'systemctl':
    assert sys.argv[1:3] == ['is-active', '--quiet']
    sys.exit(0 if profile == 'active' and sys.argv[-1] == 'ufw.service' else 3)
if name == 'dpkg-query':
    print('install ok installed' if profile == 'installed' else '')
elif name in ('iptables-save', 'ip6tables-save'):
    print('*filter\\n:INPUT ACCEPT [0:0]\\n' + (':ufw-before-input - [0:0]\\n' if profile == 'leftover' else '') + 'COMMIT')
elif name == 'nft':
    assert sys.argv[1:] == ['-j', 'list', 'tables']
    print(json.dumps({'nftables': [{'table': {'family': 'inet' if profile == 'native' else 'ip', 'name': 'custom' if profile == 'native' else 'filter'}}]}))
else:
    raise RuntimeError('Unexpected command')
"""
            for name in ("systemctl", "dpkg-query", "iptables-save", "ip6tables-save", "nft"):
                path = binary / name
                path.write_text(dispatcher)
                path.chmod(0o700)
            env = {**os.environ, "PATH": directory, "PREFLIGHT_PROFILE": profile,
                   "PREFLIGHT_CALLS": str(binary / "calls")}
            result = subprocess.run(["/bin/bash", str(ROOT / "preflight-oracle.sh")], env=env,
                                    text=True, capture_output=True, timeout=15)
            calls = (binary / "calls").read_text()
        self.assertNotIn(" stop ", calls)
        self.assertNotIn(" mask ", calls)
        return result

    def test_clean_compatibility_rules_pass(self):
        result = self.run_profile("clean")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_active_manager_stops(self):
        result = self.run_profile("active")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ufw is active", result.stderr)

    def test_installed_but_inactive_ufw_stops(self):
        result = self.run_profile("installed")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("UFW is installed", result.stderr)

    def test_leftover_chains_stop(self):
        result = self.run_profile("leftover")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("chains found", result.stderr)

    def test_native_table_stops(self):
        result = self.run_profile("native")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("native nftables table", result.stderr)


if __name__ == "__main__":
    unittest.main()

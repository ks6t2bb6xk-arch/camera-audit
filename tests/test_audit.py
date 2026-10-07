from __future__ import annotations

import io
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from camera_audit import cli, nvd, onvif, preview, scanner, storage


DISCOVERY = """<nmaprun>
<host><status state="up"/><address addr="192.168.1.20" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Hikvision"/>
<hostnames><hostname name="cam-front"/></hostnames></host>
<host><status state="up"/><address addr="192.168.1.21" addrtype="ipv4"/></host>
<host><status state="down"/><address addr="192.168.1.22" addrtype="ipv4"/></host>
</nmaprun>"""

SERVICES = """<nmaprun>
<host><status state="up"/><address addr="192.168.1.20" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="554"><state state="open"/>
<service name="rtsp" product="Example Camera" version="1.2">
<cpe>cpe:/h:example:camera:1.2</cpe></service></port></ports></host>
<host><status state="up"/><address addr="192.168.1.21" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host>
</nmaprun>"""


class StateFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"CAMERA_AUDIT_DATA_DIR": self.temp.name})
        self.env.start()
        self.db = storage.database()

    def tearDown(self):
        self.db.close()
        self.env.stop()
        self.temp.cleanup()


class StateTests(StateFixture, unittest.TestCase):

    def test_scope_requires_explicit_non_private_flag_and_exact_allowlist(self):
        storage.add_scope(self.db, "192.168.1.0/24", False)
        self.assertEqual(storage.get_scope(self.db, "192.168.1.0/24")["cidr"], "192.168.1.0/24")
        with self.assertRaises(ValueError):
            storage.get_scope(self.db, "192.168.2.0/24")
        with self.assertRaises(ValueError):
            storage.add_scope(self.db, "8.8.8.0/24", False)
        with self.assertRaises(ValueError):
            storage.add_scope(self.db, "198.18.0.0/15", False)
        cidr, non_private = storage.add_scope(self.db, "198.18.0.0/24", True)
        self.assertEqual(cidr, "198.18.0.0/24")
        self.assertTrue(non_private)
        with self.assertRaises(ValueError):
            storage.add_scope(self.db, "10.0.0.0/8", False)
        with self.assertRaises(ValueError):
            storage.add_scope(self.db, "fd00::/64", True)

    def test_scan_confirmation_is_required_each_time(self):
        self.assertFalse(cli._confirm_scan("192.168.1.0/24", False, lambda _: "no"))
        self.assertTrue(cli._confirm_scan("192.168.1.0/24", False, lambda _: "yes"))
        self.assertFalse(cli._confirm_scan("198.18.0.0/24", True, lambda _: "yes"))
        self.assertTrue(cli._confirm_scan("198.18.0.0/24", True, lambda _: "198.18.0.0/24"))

    def test_report_permissions_and_no_credentials(self):
        report = {"created_at": storage.utc_now(), "cidr": "192.168.1.0/24", "hosts": []}
        target = Path(self.temp.name) / "reports" / "scan-1.json"
        storage.export_report(report, target)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(target.parent.stat().st_mode & 0o777, 0o700)
        self.assertNotIn("password", target.read_text())


class ScanTests(unittest.TestCase):
    def test_parse_and_scan_all_live_hosts(self):
        with patch("camera_audit.scanner._run_nmap", side_effect=[DISCOVERY, SERVICES]) as run:
            hosts = scanner.scan("192.168.1.0/24", lambda _: {"192.168.1.20": "http://192.168.1.20/onvif/device_service"})
        self.assertEqual([host["ip"] for host in hosts], ["192.168.1.20", "192.168.1.21"])
        self.assertTrue(hosts[0]["camera_candidate"])
        self.assertFalse(hosts[1]["camera_candidate"])
        self.assertEqual(hosts[0]["mac_vendor"], "Hikvision")
        self.assertIn("--top-ports", run.call_args_list[1].args[0])
        self.assertIn("192.168.1.21", run.call_args_list[1].args[0])
        self.assertNotIn("192.168.1.22", run.call_args_list[1].args[0])

    def test_xml_parse_rejects_invalid_and_skips_down_hosts(self):
        self.assertEqual(len(scanner.parse_nmap(DISCOVERY)), 2)
        with self.assertRaises(scanner.ScanError):
            scanner.parse_nmap("<not-xml")


class NVDTests(StateFixture, unittest.TestCase):
    def test_versioned_cpe_and_cache_offline(self):
        cpe = nvd.normalized_cpe("cpe:/h:example:camera:1.2")
        self.assertEqual(cpe, "cpe:2.3:h:example:camera:1.2:*:*:*:*:*:*:*")
        self.assertIsNone(nvd.normalized_cpe("cpe:/h:example:camera"))
        payload = {"totalResults": 1, "resultsPerPage": 2000, "vulnerabilities": [{"cve": {
            "id": "CVE-2024-12345", "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Example issue"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
        }}]}
        response = types.SimpleNamespace(json=lambda: payload, raise_for_status=lambda: None)
        with patch("camera_audit.nvd.requests.get", return_value=response) as get:
            findings, status, timestamp = nvd.NVDClient(self.db).lookup(cpe)
        self.assertEqual(status, "live")
        self.assertEqual(findings[0]["id"], "CVE-2024-12345")
        self.assertEqual(get.call_args.kwargs["params"]["cpeName"], cpe)
        self.assertNotIn("192.168", str(get.call_args))
        self.assertNotIn("AA:BB", str(get.call_args))
        cached, status, _ = nvd.NVDClient(self.db, offline=True).lookup(cpe)
        self.assertEqual(status, "cache")
        self.assertEqual(cached, findings)

    def test_enrichment_marks_possible_impact_only(self):
        host = scanner.parse_nmap(SERVICES)[0]
        fake = types.SimpleNamespace(lookup=lambda _: ([{"id": "CVE-2024-12345", "status": "potential impact"}], "cache", "2026-01-01"))
        nvd.enrich_hosts([host], fake)
        self.assertEqual(host["vulnerabilities"][0]["status"], "potential impact")
        self.assertEqual(host["vulnerabilities"][0]["evidence"]["port"], 554)


class PreviewTests(unittest.TestCase):
    def test_url_must_match_approved_ip_and_not_embed_password(self):
        self.assertEqual(onvif.validate_device_url("rtsp://192.168.1.20:554/live", "192.168.1.20", ("rtsp",)),
                         "rtsp://192.168.1.20:554/live")
        with self.assertRaises(ValueError):
            onvif.validate_device_url("rtsp://user:secret@192.168.1.20/live", "192.168.1.20", ("rtsp",))
        with self.assertRaises(ValueError):
            onvif.validate_device_url("rtsp://8.8.8.8/live", "192.168.1.20", ("rtsp",))

    def test_ffplay_receives_raw_frames_without_secrets_or_output_file(self):
        class Plane:
            line_size = 6
            def __bytes__(self):
                return b"abcdef"
        frame = types.SimpleNamespace(width=2, height=1, planes=[Plane()])
        frame.reformat = lambda format: frame
        class Source:
            streams = [types.SimpleNamespace(type="video", average_rate=25)]
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def decode(self, stream): yield frame
        class Player:
            def __init__(self, command, **kwargs):
                self.command = command
                self.stdin = io.BytesIO()
                self.stopped = False
            def poll(self): return 0 if self.stopped else None
            def terminate(self): self.stopped = True
            def wait(self, timeout=None): return 0
        holder = {}
        def popen(command, **kwargs):
            holder["player"] = Player(command, **kwargs)
            return holder["player"]
        fake_av = types.SimpleNamespace(logging=types.SimpleNamespace(PANIC=0, set_level=lambda _: None),
                                        open=lambda *args, **kwargs: Source())
        with patch.dict("sys.modules", {"av": fake_av}), patch("camera_audit.preview.shutil.which", return_value="/usr/bin/ffplay"), patch("camera_audit.preview.subprocess.Popen", side_effect=popen):
            self.assertTrue(preview.play("rtsp://192.168.1.20/live", "192.168.1.20", "admin", "secret"))
        command = holder["player"].command
        self.assertNotIn("secret", " ".join(command))
        self.assertNotIn("admin", " ".join(command))
        self.assertNotIn("-record", command)
        self.assertTrue(holder["player"].stopped)


class CLITests(StateFixture, unittest.TestCase):
    def test_offline_scan_report_and_explicit_camera_approval(self):
        self.assertEqual(cli.main(["scope", "add", "192.168.1.0/24"]), 0)
        hosts = scanner.parse_nmap(SERVICES)
        for host in hosts:
            host["onvif_url"] = None
            host["camera_evidence"] = scanner.candidate_evidence(host)
            host["camera_candidate"] = bool(host["camera_evidence"])
        with patch("builtins.input", return_value="yes"), \
             patch("camera_audit.cli.scanner.scan", return_value=hosts), \
             patch("camera_audit.cli.enrich_hosts", side_effect=lambda found, client: None):
            self.assertEqual(cli.main(["scan", "192.168.1.0/24", "--offline"]), 0)
        report = json.loads((Path(self.temp.name) / "reports" / "scan-1.json").read_text())
        self.assertEqual(len(report["hosts"]), 2)
        self.assertTrue(report["hosts"][0]["camera_candidate"])
        self.assertFalse(report["hosts"][1]["camera_candidate"])
        self.assertEqual(cli.main(["cameras", "approve", "192.168.1.20", "--rtsp-url", "rtsp://192.168.1.20/live"]), 0)
        with storage.database() as db:
            self.assertIsNotNone(storage.get_camera(db, "192.168.1.20"))
            self.assertIsNone(storage.get_camera(db, "192.168.1.21"))


if __name__ == "__main__":
    unittest.main()

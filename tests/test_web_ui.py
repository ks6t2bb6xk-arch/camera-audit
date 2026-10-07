from __future__ import annotations

import http.client
import ipaddress
import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from camera_audit import cli, local_network, preview, rtsp_discovery, scanner, storage, web_ui


CIDR = "192.168.1.0/24"
IP = "192.168.1.20"
PASSWORD = "private-test-password-unique"


def camera_host():
    return {"ip": IP, "hostname": "front-camera", "mac": "AA:BB:CC:DD:EE:FF",
            "mac_vendor": "Example", "ports": [{"protocol": "tcp", "port": 554, "service": "rtsp",
                                                "product": "Camera", "version": "1.0", "cpes": []}],
            "onvif_url": None, "onvif_uuid": None, "camera_candidate": True,
            "camera_evidence": ["RTSP indicator: TCP 554"]}


class WebSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"CAMERA_AUDIT_DATA_DIR": self.temp.name})
        self.env.start()
        network = local_network.LocalNetwork("en0", ipaddress.IPv4Address("192.168.1.34"),
                                             ipaddress.IPv4Network(CIDR))
        self.detect = patch("camera_audit.web_ui.local_network.detect", return_value=network)
        self.detect.start()
        self.session = web_ui.Session()

    def tearDown(self):
        self.session.close()
        if self.session.worker:
            self.session.worker.join(timeout=2)
        self.detect.stop()
        self.env.stop()
        self.temp.cleanup()

    def wait_for(self, condition, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.session.snapshot()
            if condition(state):
                return state
            time.sleep(0.01)
        self.fail(f"Timed out waiting for session state: {self.session.snapshot()}")

    def seed_camera_scan(self, host):
        with storage.database() as db:
            storage.add_scope(db, CIDR, False)
            report = {"created_at": storage.utc_now(), "cidr": CIDR, "hosts": [host]}
            scan_id = storage.save_scan(db, report)
        self.session.mode = "scan_watch"
        self.session.phase = "scan_complete"
        self.session.scan_id = scan_id
        self.session.report = report
        return scan_id

    def answer_prompt(self, kind, answer):
        prompt = self.wait_for(lambda item: item["prompt"] is not None)["prompt"]
        self.assertEqual(prompt["kind"], kind)
        self.session.respond(prompt["id"], answer)

    def test_default_cli_opens_browser_interface_and_commands_remain(self):
        with patch("camera_audit.web_ui.serve", return_value=0) as serve:
            self.assertEqual(cli.main([]), 0)
        serve.assert_called_once_with()
        self.assertEqual(cli._parser().parse_args(["scan", "--local"]).command, "scan")
        self.assertEqual(cli._parser().parse_args(["watch"]).command, "watch")

    def test_authorized_scan_uses_detected_or_edited_cidr_and_saves_report(self):
        self.assertEqual(self.session.snapshot()["network"],
                         {"interface": "en0", "address": "192.168.1.34", "cidr": CIDR})
        with self.assertRaisesRegex(ValueError, "Confirm authorization"):
            self.session.start_scan("scan", CIDR, "")
        self.assertIsNone(self.session.worker)

        host = camera_host()
        def scan(cidr, discovery, progress=None, cancel_event=None):
            self.assertEqual(cidr, CIDR)
            progress("Fingerprinting services")
            return [host]
        with patch("camera_audit.audit_scan.scanner.scan", side_effect=scan), \
             patch("camera_audit.audit_scan.enrich_hosts", side_effect=lambda hosts, client, cancel_event=None: None):
            self.session.start_scan("scan", CIDR, "yes")
            state = self.wait_for(lambda item: item["phase"] == "scan_complete")
        self.assertEqual(state["host_count"], 1)
        self.assertEqual(state["candidate_count"], 1)
        self.assertEqual(self.session.results()["hosts"][0]["ip"], IP)
        report = Path(state["report_path"])
        self.assertTrue(report.exists())
        self.assertEqual(json.loads(report.read_text())["hosts"][0]["ip"], IP)
        with storage.database() as db:
            self.assertEqual(storage.get_scope(db, CIDR)["cidr"], CIDR)

    def test_non_private_target_requires_exact_cidr(self):
        target = "198.18.0.0/24"
        with self.assertRaisesRegex(ValueError, "Confirm authorization"):
            self.session.start_scan("scan", target, "yes")
        with patch("camera_audit.audit_scan.scanner.scan", return_value=[]), \
             patch("camera_audit.audit_scan.enrich_hosts", side_effect=lambda hosts, client, cancel_event=None: None):
            self.session.start_scan("scan", target, target)
            self.wait_for(lambda item: item["phase"] == "scan_complete")
        with storage.database() as db:
            self.assertTrue(storage.get_scope(db, target)["non_private"])

    def test_cancelled_scan_does_not_save_a_report(self):
        started = threading.Event()
        def slow_scan(cidr, discovery, progress=None, cancel_event=None):
            started.set()
            if not cancel_event.wait(timeout=2):
                self.fail("Cancellation was not delivered to the scan worker")
            raise scanner.ScanCancelled("Scan cancelled.")
        with patch("camera_audit.audit_scan.scanner.scan", side_effect=slow_scan):
            self.session.start_scan("scan", CIDR, "yes")
            self.assertTrue(started.wait(timeout=2))
            self.session.cancel_scan()
            self.wait_for(lambda item: item["phase"] == "cancelled")
        self.assertIsNone(self.session.scan_id)
        self.assertIsNone(self.session.report_path)
        with storage.database() as db:
            self.assertIsNone(storage.latest_scan(db))

    def test_cancelled_nmap_process_is_terminated(self):
        cancelled = threading.Event()
        class Process:
            returncode = None
            terminated = False
            def communicate(self, timeout=None):
                if not self.terminated:
                    cancelled.set()
                    raise subprocess.TimeoutExpired("nmap", timeout)
                return "", ""
            def terminate(self):
                self.terminated = True
                self.returncode = -15
        process = Process()
        with patch("camera_audit.scanner.subprocess.Popen", return_value=process):
            with self.assertRaises(scanner.ScanCancelled):
                scanner._run_nmap(["-sn", CIDR], 3, cancelled)
        self.assertTrue(process.terminated)

    def test_nmap_cancel_handles_process_exit_race(self):
        cancelled = threading.Event()
        class Process:
            returncode = 0
            calls = 0
            def communicate(self, timeout=None):
                self.calls += 1
                if self.calls == 1:
                    cancelled.set()
                    raise subprocess.TimeoutExpired("nmap", timeout)
                return "", ""
            def terminate(self):
                raise ProcessLookupError
        with patch("camera_audit.scanner.subprocess.Popen", return_value=Process()):
            with self.assertRaises(scanner.ScanCancelled):
                scanner._run_nmap(["-sn", CIDR], 3, cancelled)

    def test_results_are_paged_and_camera_candidates_can_be_filtered(self):
        hosts = []
        for index in range(125):
            host = {"ip": f"192.168.1.{index + 1}", "camera_candidate": index % 10 == 0,
                    "vulnerabilities": [{"id": "CVE-TEST"}] if index % 25 == 0 else []}
            hosts.append(host)
        self.session.scan_id = 7
        self.session.report = {"cidr": CIDR, "created_at": storage.utc_now(), "hosts": hosts}
        first = self.session.results()
        self.assertEqual((first["total_hosts"], first["total_candidates"], first["total_findings"]),
                         (125, 13, 5))
        self.assertEqual((first["page"], first["total_pages"], first["first"], first["last"]),
                         (1, 3, 1, 50))
        self.assertEqual(len(first["hosts"]), 50)
        last = self.session.results(3)
        self.assertEqual((last["first"], last["last"], len(last["hosts"])), (101, 125, 25))
        cameras = self.session.results(1, True)
        self.assertEqual((cameras["total_pages"], cameras["first"], cameras["last"]), (1, 1, 13))
        self.assertTrue(all(host["camera_candidate"] for host in cameras["hosts"]))
        with self.assertRaisesRegex(ValueError, "outside"):
            self.session.results(4)

    def test_scan_watch_prompts_for_auth_and_preview_without_leaking_password(self):
        host = camera_host()
        self.seed_camera_scan(host)
        with self.assertRaisesRegex(ValueError, "candidate"):
            self.session.start_watch("192.168.1.99")
        challenge = rtsp_discovery.ProbeResult(f"rtsp://{IP}:554/live", "auth_required", "Basic authentication required")
        verified = rtsp_discovery.ProbeResult(f"rtsp://{IP}:554/live", "valid", "Valid video SDP")
        with patch("camera_audit.rtsp_discovery.discover", return_value=[challenge]), \
             patch("camera_audit.rtsp_discovery.probe", return_value=verified) as probe, \
             patch.object(preview, "save_password") as save_password, \
             patch.object(preview, "play", return_value=True) as play:
            self.session.start_watch(IP)
            expected = [("confirm", True), ("choose", 0),
                        ("credentials", {"username": "admin", "password": PASSWORD}),
                        ("confirm", True), ("confirm", True)]
            for kind, answer in expected:
                state = self.wait_for(lambda item: item["prompt"] is not None)
                prompt = state["prompt"]
                self.assertEqual(prompt["kind"], kind)
                self.assertNotIn(PASSWORD, json.dumps(state))
                self.session.respond(prompt["id"], answer)
            self.wait_for(lambda item: item["phase"] == "watch_complete")
        self.assertEqual(probe.call_args.args[3:5], ("admin", PASSWORD))
        save_password.assert_called()
        play.assert_called_once()
        with storage.database() as db:
            self.assertNotIn(PASSWORD, "\n".join(db.iterdump()))
        self.assertNotIn(PASSWORD, json.dumps(self.session.report_json()))
        self.assertNotIn(PASSWORD, json.dumps(self.session.snapshot()))

    def test_scan_watch_selects_onvif_profile_in_browser_flow(self):
        host = camera_host()
        host["onvif_url"] = f"http://{IP}/onvif/device_service"
        scan_id = self.seed_camera_scan(host)
        profiles = [{"name": "Main", "token": "main", "media_url": f"http://{IP}/media"},
                    {"name": "Sub", "token": "sub", "media_url": f"http://{IP}/media"}]
        with patch("camera_audit.onvif.list_profiles", return_value=profiles), \
             patch("camera_audit.onvif.stream_uri_for_profile", return_value=f"rtsp://{IP}/live") as uri, \
             patch.object(preview, "play", return_value=True):
            self.session.start_watch(IP)
            self.answer_prompt("confirm", True)
            self.answer_prompt("choose", 1)
            self.answer_prompt("confirm", True)
            self.wait_for(lambda item: item["phase"] == "watch_complete")
        self.assertEqual(uri.call_args.args[0]["token"], "sub")
        with storage.database() as db:
            key = storage.host_identity(host, scan_id)[0]
            self.assertEqual(storage.get_connection(db, key)["profile_token"], "sub")

    def test_scan_watch_accepts_manual_url_only_for_selected_camera(self):
        host = camera_host()
        self.seed_camera_scan(host)
        manual = f"rtsp://{IP}:554/custom"
        with patch("camera_audit.rtsp_discovery.discover", return_value=[]), \
             patch.object(preview, "play", return_value=True) as play:
            self.session.start_watch(IP)
            self.answer_prompt("confirm", True)
            self.answer_prompt("manual_url", manual)
            self.answer_prompt("confirm", True)
            self.wait_for(lambda item: item["phase"] == "watch_complete")
        self.assertEqual(play.call_args.args[0], manual)

    def test_http_requires_session_token_and_stays_on_loopback(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), web_ui._handler(self.session))
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.assertEqual(server.server_address[0], "127.0.0.1")
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            conn.request("GET", "/")
            response = conn.getresponse()
            page = response.read().decode()
            self.assertEqual(response.status, 200)
            self.assertIn("Scan only", page)
            self.assertIn("Scan + Watch", page)
            conn.request("GET", "/api/state")
            response = conn.getresponse()
            response.read()
            self.assertEqual(response.status, 403)
            conn.request("GET", "/api/state", headers={"X-Camera-Audit-Token": self.session.token})
            response = conn.getresponse()
            state = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertEqual(state["network"]["cidr"], CIDR)
            self.assertNotIn(self.session.token, json.dumps(state))
            self.session.scan_id = 1
            self.session.report = {"cidr": CIDR, "created_at": storage.utc_now(),
                                   "hosts": [camera_host()]}
            conn.request("GET", "/api/results?page=1&candidates=1",
                         headers={"X-Camera-Audit-Token": self.session.token})
            response = conn.getresponse()
            results = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertEqual((results["total_candidates"], results["last"]), (1, 1))
            conn.request("GET", "/api/results?page=2",
                         headers={"X-Camera-Audit-Token": self.session.token})
            response = conn.getresponse()
            response.read()
            self.assertEqual(response.status, 400)
            body = json.dumps({"cidr": CIDR})
            headers = {"X-Camera-Audit-Token": self.session.token, "Content-Type": "application/json",
                       "Origin": "https://example.invalid"}
            conn.request("POST", "/api/target", body=body, headers=headers)
            response = conn.getresponse()
            response.read()
            self.assertEqual(response.status, 403)
            headers["Origin"] = f"http://127.0.0.1:{server.server_port}"
            conn.request("POST", "/api/target", body=body, headers=headers)
            response = conn.getresponse()
            target = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertEqual(target, {"cidr": CIDR, "non_private": False})
            conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

from camera_audit import cli, onvif, preview, rtsp_discovery, storage, watch


CAMERA_IP = "192.168.1.20"
RTSP_URL = f"rtsp://{CAMERA_IP}:554/live"
ONVIF_URL = f"http://{CAMERA_IP}/onvif/device_service"


class WatchFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"CAMERA_AUDIT_DATA_DIR": self.temp.name})
        self.env.start()
        self.db = storage.database()
        storage.add_scope(self.db, "192.168.1.0/24", False)
        self.host = {"ip": CAMERA_IP, "mac": "AA:BB:CC:DD:EE:FF", "mac_vendor": "Example",
                     "onvif_url": ONVIF_URL, "onvif_uuid": None, "camera_candidate": True,
                     "camera_evidence": ["RTSP indicator"],
                     "ports": [{"port": 554, "protocol": "tcp", "service": "rtsp"}]}
        self.scan_id = self.save_scan(self.host)

    def tearDown(self):
        self.db.close()
        self.env.stop()
        self.temp.cleanup()

    def save_scan(self, host):
        return storage.save_scan(self.db, {"created_at": storage.utc_now(),
                                          "cidr": "192.168.1.0/24", "hosts": [host]})

    def approved_record(self, url=RTSP_URL):
        record = watch._fresh_record(self.host, self.scan_id, self.db)
        record.update(approved_ip=CAMERA_IP, approved_at=storage.utc_now(),
                      rtsp_url=url, verification_status="preview_opened")
        storage.save_connection(self.db, record)
        return record


class WatchTests(WatchFixture):
    def test_onvif_profiles_and_stream_uri_are_reused_without_extra_profile_fetch(self):
        capabilities = ET.fromstring("<Envelope><Media><XAddr>http://192.168.1.20/media</XAddr></Media></Envelope>")
        profiles = ET.fromstring("<Envelope><Profiles token='main'><Name>Main</Name></Profiles><Profiles token='sub'><Name>Sub</Name></Profiles></Envelope>")
        stream = ET.fromstring("<Envelope><Uri>rtsp://192.168.1.20:554/live</Uri></Envelope>")
        with patch.object(onvif, "_request", side_effect=[capabilities, profiles, stream]) as request:
            found = onvif.list_profiles(ONVIF_URL, CAMERA_IP, None, None)
            self.assertEqual([item["name"] for item in found], ["Main", "Sub"])
            uri = onvif.stream_uri_for_profile(found[1], CAMERA_IP, None, None)
        self.assertEqual(uri, RTSP_URL)
        self.assertEqual(request.call_count, 3)

    def test_onvif_without_media_endpoint_is_explained(self):
        with patch.object(onvif, "_request", return_value=ET.fromstring("<Envelope/>")):
            with self.assertRaises(onvif.OnvifError):
                onvif.list_profiles(ONVIF_URL, CAMERA_IP, None, None)

    def test_onvif_401_is_distinct_and_does_not_follow_redirects(self):
        class Response:
            status_code = 401
        with patch("camera_audit.onvif.requests.post", return_value=Response()) as post:
            with self.assertRaises(onvif.OnvifAuthRequired):
                onvif._request(ONVIF_URL, CAMERA_IP, "<Probe/>", None, None)
        self.assertFalse(post.call_args.kwargs["allow_redirects"])

    def test_onvif_stream_uri_cannot_redirect_to_another_ip(self):
        profile = {"token": "main", "media_url": f"http://{CAMERA_IP}/media"}
        response = ET.fromstring("<Envelope><Uri>rtsp://192.168.1.99/live</Uri></Envelope>")
        with patch.object(onvif, "_request", return_value=response):
            with self.assertRaises(ValueError):
                onvif.stream_uri_for_profile(profile, CAMERA_IP, None, None)

    def test_cancelled_selection_does_not_discover_or_play(self):
        with patch("builtins.input", return_value="0"), \
             patch.object(rtsp_discovery, "discover") as discover, \
             patch.object(preview, "play") as play:
            self.assertEqual(watch.run(self.db), 0)
        discover.assert_not_called()
        play.assert_not_called()

    def test_missing_scan_offers_local_scan_without_starting_it_implicitly(self):
        self.db.execute("DELETE FROM scans")
        self.db.commit()
        with patch("builtins.input", return_value="no"):
            self.assertEqual(watch.run(self.db, scan_local=lambda: self.fail("scan started")), 1)
        def scan_local():
            self.save_scan(self.host)
            return 0
        with patch("builtins.input", side_effect=["yes", "0"]):
            self.assertEqual(watch.run(self.db, scan_local=scan_local), 0)

    def test_saved_verified_url_is_reused_and_success_recorded(self):
        record = self.approved_record()
        with patch("builtins.input", return_value="yes"), \
             patch.object(onvif, "list_profiles") as profiles, \
             patch.object(rtsp_discovery, "discover") as discover, \
             patch.object(preview, "play", return_value=True) as play:
            self.assertEqual(watch.run(self.db, CAMERA_IP), 0)
        profiles.assert_not_called()
        discover.assert_not_called()
        play.assert_called_once_with(RTSP_URL, CAMERA_IP, None, None)
        saved = storage.get_connection(self.db, record["device_key"])
        self.assertIsNotNone(saved["last_success_at"])

    def test_ip_change_or_identity_change_clears_approval_and_saved_url(self):
        self.approved_record()
        moved = {**self.host, "ip": "192.168.1.21", "onvif_url": None}
        moved_scan = self.save_scan(moved)
        moved_record = watch._fresh_record(moved, moved_scan, self.db)
        self.assertIsNone(moved_record["approved_ip"])
        self.assertIsNone(moved_record["rtsp_url"])
        replaced = {**self.host, "mac": "11:22:33:44:55:66"}
        replacement = watch._fresh_record(replaced, self.scan_id, self.db)
        self.assertIsNone(replacement["approved_ip"])
        self.assertNotEqual(replacement["device_key"], moved_record["device_key"])

    def test_unknown_identity_is_bound_to_one_scan(self):
        unknown = {**self.host, "mac": None, "onvif_uuid": None}
        first_key = storage.host_identity(unknown, self.scan_id)[0]
        next_key = storage.host_identity(unknown, self.save_scan(unknown))[0]
        self.assertNotEqual(first_key, next_key)

    def test_unauthorized_scope_or_host_is_rejected_before_network_access(self):
        self.db.execute("DELETE FROM scopes")
        self.db.commit()
        with patch.object(rtsp_discovery, "discover") as discover:
            with self.assertRaises(ValueError):
                watch.run(self.db, CAMERA_IP)
        discover.assert_not_called()

    def test_host_outside_report_cidr_is_rejected(self):
        outside = {**self.host, "ip": "10.0.0.5"}
        self.save_scan(outside)
        with self.assertRaises(ValueError):
            storage.authorized_candidate(self.db, outside["ip"])

    def test_credential_store_failure_is_reflected_in_status(self):
        record = self.approved_record()
        record.update(username="admin", auth_required=1)
        storage.save_connection(self.db, record)
        with patch.object(preview, "load_password", side_effect=preview.PreviewError("Unavailable")):
            self.assertEqual(watch._status(self.host, self.scan_id, self.db), "Authentication Required")

    def test_onvif_discovery_and_preview_save_success(self):
        profiles = [{"token": "main", "name": "Main", "media_url": f"http://{CAMERA_IP}/media"}]
        with patch("builtins.input", side_effect=["yes", "yes"]), \
             patch.object(onvif, "list_profiles", return_value=profiles), \
             patch.object(onvif, "stream_uri_for_profile", return_value=RTSP_URL), \
             patch.object(preview, "play", return_value=True):
            self.assertEqual(watch.run(self.db, CAMERA_IP), 0)
        key = storage.host_identity(self.host, self.scan_id)[0]
        saved = storage.get_connection(self.db, key)
        self.assertEqual(saved["profile_token"], "main")
        self.assertEqual(saved["verification_status"], "preview_opened")

    def test_onvif_failure_falls_back_to_bounded_rtsp_discovery(self):
        result = rtsp_discovery.ProbeResult(RTSP_URL, "valid", "Valid video SDP")
        with patch("builtins.input", side_effect=["yes", "yes"]), \
             patch.object(onvif, "list_profiles", side_effect=onvif.OnvifError("Unavailable")), \
             patch.object(rtsp_discovery, "discover", return_value=[result]) as discover, \
             patch.object(preview, "play", return_value=True):
            self.assertEqual(watch.run(self.db, CAMERA_IP), 0)
        discover.assert_called_once()
        self.assertEqual(discover.call_args.args[1], [554])

    def test_authentication_is_one_selected_rtsp_attempt_and_password_is_not_in_sqlite(self):
        password = "s3cr3t-password-unique"
        challenge = rtsp_discovery.ProbeResult(RTSP_URL, "auth_required", "RTSP authentication required")
        verified = rtsp_discovery.ProbeResult(RTSP_URL, "valid", "Valid video SDP")
        self.host["onvif_url"] = None
        self.save_scan(self.host)
        with patch("builtins.input", side_effect=["yes", "1", "admin", "yes"]), \
             patch("camera_audit.watch.getpass.getpass", return_value=password), \
             patch.object(rtsp_discovery, "discover", return_value=[challenge]), \
             patch.object(rtsp_discovery, "probe", return_value=verified) as probe, \
             patch.object(preview, "save_password") as save_password, \
             patch.object(preview, "play", return_value=True):
            self.assertEqual(watch.run(self.db, CAMERA_IP), 0)
        self.assertEqual(probe.call_count, 1)
        self.assertEqual(probe.call_args.args[3:5], ("admin", password))
        save_password.assert_called()
        self.assertNotIn(password, "\n".join(self.db.iterdump()))

    def test_inspect_never_starts_video(self):
        with patch("builtins.input", return_value="no"), patch.object(preview, "play") as play:
            self.assertEqual(watch.inspect(self.db, CAMERA_IP), 0)
        play.assert_not_called()

    def test_new_cli_commands_parse_without_changing_existing_commands(self):
        self.assertEqual(cli._parser().parse_args(["watch"]).command, "watch")
        self.assertEqual(cli._parser().parse_args(["watch", CAMERA_IP]).ip, CAMERA_IP)
        self.assertEqual(cli._parser().parse_args(["cameras", "inspect", CAMERA_IP]).camera_command, "inspect")
        self.assertEqual(cli._parser().parse_args(["preview", CAMERA_IP]).command, "preview")

    def test_secret_bearing_stream_url_is_kept_out_of_sqlite(self):
        record = watch._fresh_record(self.host, self.scan_id, self.db)
        secret_url = RTSP_URL + "?token=secret"
        with patch.object(preview, "save_stream_url") as save_url:
            watch._remember(self.db, record, secret_url, None, None, None, "discovered")
        save_url.assert_called_once_with(record["device_key"], secret_url)
        saved = storage.get_connection(self.db, record["device_key"])
        self.assertIsNone(saved["rtsp_url"])
        self.assertEqual(saved["rtsp_url_secret"], 1)


if __name__ == "__main__":
    unittest.main()


class MigrationTests(unittest.TestCase):
    def test_v01_camera_rows_survive_schema_migration_without_automatic_identity_approval(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"CAMERA_AUDIT_DATA_DIR": temporary}):
            target = os.path.join(temporary, "camera-audit.sqlite3")
            with sqlite3.connect(target) as old:
                old.execute("CREATE TABLE cameras (ip TEXT PRIMARY KEY, approved_at TEXT NOT NULL, rtsp_url TEXT, onvif_url TEXT, username TEXT)")
                old.execute("INSERT INTO cameras VALUES (?, ?, ?, ?, ?)",
                            (CAMERA_IP, "2026-01-01", RTSP_URL, None, "admin"))
            with storage.database() as upgraded:
                row = storage.get_camera(upgraded, CAMERA_IP)
                self.assertEqual(row["rtsp_url"], RTSP_URL)
                self.assertIsNone(row["device_key"])
                self.assertEqual(upgraded.execute("PRAGMA user_version").fetchone()[0], 2)

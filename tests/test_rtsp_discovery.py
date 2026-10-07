from __future__ import annotations

import time
import unittest
from unittest.mock import patch

from camera_audit import rtsp_discovery as rtsp


SDP = b"v=0\r\no=- 1 1 IN IP4 192.168.1.20\r\ns=Camera\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\n"


class RTSPDiscoveryTests(unittest.TestCase):
    def test_default_discovery_includes_previously_working_live_ch0_path(self):
        def probe(ip, port, path):
            status = "valid" if path == "live/ch0" else "not_found"
            return rtsp.ProbeResult(f"rtsp://{ip}:{port}/{path}", status)

        with patch.object(rtsp, "probe", side_effect=probe):
            results = rtsp.discover("192.168.1.20", [554])

        verified = [result.url for result in results if result.status == "valid"]
        self.assertEqual(verified, ["rtsp://192.168.1.20:554/live/ch0"])

    def test_valid_video_sdp_is_a_verified_endpoint(self):
        responses = [rtsp._Response(200, {}, b""),
                     rtsp._Response(200, {"content-type": "application/sdp"}, SDP)]
        with patch.object(rtsp, "_exchange", side_effect=responses) as exchange:
            result = rtsp.probe("192.168.1.20", 554, "stream1")
        self.assertEqual(result.status, "valid")
        self.assertEqual([call.args[3] for call in exchange.call_args_list], ["OPTIONS", "DESCRIBE"])

    def test_html_or_http_is_never_accepted_as_sdp(self):
        responses = [rtsp._Response(200, {}, b""),
                     rtsp._Response(200, {"content-type": "text/html"}, b"<html>login</html>")]
        with patch.object(rtsp, "_exchange", side_effect=responses):
            self.assertEqual(rtsp.probe("192.168.1.20", 554, "live").status, "unavailable")

        class Socket:
            def __init__(self):
                self.chunks = [b"HTTP/1.1 200 OK\r\nContent-Type: application/sdp\r\n\r\n" + SDP]
            def settimeout(self, _):
                pass
            def recv(self, _):
                return self.chunks.pop(0) if self.chunks else b""
        with self.assertRaises(rtsp._ProbeFailure):
            rtsp._read_response(Socket(), time.monotonic() + 1, True)

    def test_auth_required_404_timeout_and_invalid_path(self):
        for response, status in ((rtsp._Response(401, {"www-authenticate": "Digest realm=cam, nonce=abc"}, b""), "auth_required"),
                                 (rtsp._Response(404, {}, b""), "not_found")):
            with self.subTest(status=status), patch.object(rtsp, "_exchange", side_effect=[rtsp._Response(200, {}, b""), response]):
                self.assertEqual(rtsp.probe("192.168.1.20", 554, "live").status, status)
        with patch.object(rtsp, "_exchange", side_effect=rtsp._ProbeTimeout):
            self.assertEqual(rtsp.probe("192.168.1.20", 554, "live").status, "timeout")
        with self.assertRaises(ValueError):
            rtsp.probe("192.168.1.20", 554, "../secret")

    def test_user_supplied_digest_credentials_are_sent_once_without_password(self):
        responses = [rtsp._Response(200, {}, b""),
                     rtsp._Response(401, {"www-authenticate": 'Digest realm="cam", nonce="abc", qop="auth"'}, b""),
                     rtsp._Response(200, {"content-type": "application/sdp"}, SDP)]
        with patch.object(rtsp, "_exchange", side_effect=responses) as exchange:
            result = rtsp.probe("192.168.1.20", 554, "live", "admin", "secret")
        self.assertEqual(result.status, "valid")
        self.assertEqual(exchange.call_count, 3)
        authorization = exchange.call_args_list[2].args[4]
        self.assertIn("Digest ", authorization)
        self.assertNotIn("secret", authorization)

    def test_basic_auth_needs_explicit_permission(self):
        challenge = rtsp._Response(401, {"www-authenticate": 'Basic realm="cam"'}, b"")
        with patch.object(rtsp, "_exchange", side_effect=[rtsp._Response(200, {}, b""), challenge]) as exchange:
            result = rtsp.probe("192.168.1.20", 554, "live", "admin", "secret")
        self.assertEqual(result.status, "auth_required")
        self.assertEqual(exchange.call_count, 2)


if __name__ == "__main__":
    unittest.main()

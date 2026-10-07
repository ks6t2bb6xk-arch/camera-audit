"""Local, session-protected browser interface for camera-audit."""

from __future__ import annotations

import ipaddress
import json
import queue
import secrets
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.parse import parse_qs, urlsplit

from . import audit_scan, local_network, onvif, preview, scanner, storage, watch


class WebInteraction:
    def __init__(self, session: "Session"):
        self.session = session

    def _ask(self, kind: str, message: str, **details):
        response = self.session.ask(kind, message, **details)
        if response is None:
            raise watch.Cancelled
        return response

    def confirm(self, message: str) -> bool:
        return self._ask("confirm", message) is True

    def choose(self, message: str, options: list[str]) -> int:
        answer = self._ask("choose", message, options=options)
        if not isinstance(answer, int) or isinstance(answer, bool) or not 0 <= answer < len(options):
            raise watch.Cancelled
        return answer

    def credentials(self, suggested: str | None) -> tuple[str, str]:
        answer = self._ask("credentials", "Enter camera credentials.", username=suggested or "")
        if not isinstance(answer, dict):
            raise watch.Cancelled
        username = answer.get("username")
        password = answer.get("password")
        if not isinstance(username, str) or not username.strip() or not isinstance(password, str) or not password:
            raise watch.Cancelled
        return username.strip(), password

    def manual_url(self, ip: str) -> str | None:
        answer = self._ask("manual_url", f"Enter an RTSP URL for {ip}, or cancel.")
        if not isinstance(answer, str) or not answer.strip():
            return None
        return onvif.validate_device_url(answer.strip(), ip, ("rtsp", "rtsps"))

    def notice(self, message: str) -> None:
        self.session.message(message)


class Session:
    RESULTS_PAGE_SIZE = 50

    def __init__(self):
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.worker: threading.Thread | None = None
        self.cancel_event: threading.Event | None = None
        self.pending_reply: queue.Queue | None = None
        self.prompt: dict | None = None
        self.mode: str | None = None
        self.phase = "ready"
        self.message_text = "Choose a mode to begin."
        self.error: str | None = None
        self.scan_id: int | None = None
        self.report: dict | None = None
        self.report_path: str | None = None
        self.network: dict | None = None
        self.network_error: str | None = None
        try:
            detected = local_network.detect()
            self.network = {"interface": detected.interface,
                            "address": str(detected.address), "cidr": str(detected.network)}
        except (ValueError, OSError) as exc:
            self.network_error = str(exc)

    def snapshot(self) -> dict:
        with self.lock:
            hosts = self.report["hosts"] if self.report else []
            return {"mode": self.mode, "phase": self.phase, "message": self.message_text,
                    "error": self.error, "scan_id": self.scan_id,
                    "host_count": len(hosts),
                    "candidate_count": sum(bool(host.get("camera_candidate")) for host in hosts),
                    "report_path": self.report_path, "prompt": self.prompt,
                    "network": self.network, "network_error": self.network_error}

    def results(self, page: int = 1, candidates_only: bool = False) -> dict:
        if page < 1:
            raise ValueError("Page must be a positive integer.")
        with self.lock:
            if self.report is None:
                raise ValueError("No scan result is available.")
            all_hosts = self.report["hosts"]
            hosts = ([host for host in all_hosts if host.get("camera_candidate")]
                     if candidates_only else all_hosts)
            total_pages = max(1, (len(hosts) + self.RESULTS_PAGE_SIZE - 1) // self.RESULTS_PAGE_SIZE)
            if page > total_pages:
                raise ValueError("Page is outside the scan results.")
            start = (page - 1) * self.RESULTS_PAGE_SIZE
            selected = hosts[start:start + self.RESULTS_PAGE_SIZE]
            return {"scan_id": self.scan_id, "cidr": self.report["cidr"],
                    "created_at": self.report["created_at"],
                    "total_hosts": len(all_hosts),
                    "total_candidates": sum(bool(host.get("camera_candidate")) for host in all_hosts),
                    "total_findings": sum(len(host.get("vulnerabilities") or []) for host in all_hosts),
                    "page": page, "total_pages": total_pages, "candidates_only": candidates_only,
                    "first": start + 1 if selected else 0,
                    "last": start + len(selected) if selected else 0,
                    "hosts": selected}

    def report_json(self) -> dict:
        with self.lock:
            if self.report is None:
                raise ValueError("No scan report is available.")
            return self.report

    def message(self, value: str) -> None:
        with self.lock:
            if self.phase != "cancelling":
                self.message_text = value

    def ask(self, kind: str, message: str, **details):
        answer_queue: queue.Queue = queue.Queue(maxsize=1)
        prompt_id = secrets.token_hex(12)
        with self.lock:
            self.prompt = {"id": prompt_id, "kind": kind, "message": message, **details}
            self.pending_reply = answer_queue
            self.phase = "waiting_for_input"
        try:
            return answer_queue.get(timeout=1800)
        except queue.Empty:
            raise watch.Cancelled from None
        finally:
            with self.lock:
                if self.prompt and self.prompt["id"] == prompt_id:
                    self.prompt = None
                    self.pending_reply = None
                    self.phase = "working"

    def respond(self, prompt_id: str, answer) -> None:
        with self.lock:
            if self.prompt is None or self.prompt["id"] != prompt_id or self.pending_reply is None:
                raise ValueError("This prompt is no longer active.")
            kind = self.prompt["kind"]
            if kind == "confirm" and answer is not None and not isinstance(answer, bool):
                raise ValueError("Invalid confirmation.")
            if kind == "choose" and answer is not None and (not isinstance(answer, int) or isinstance(answer, bool)
                    or not 0 <= answer < len(self.prompt["options"])):
                raise ValueError("Invalid selection.")
            if kind == "credentials" and answer is not None and (not isinstance(answer, dict)
                    or not isinstance(answer.get("username"), str)
                    or not isinstance(answer.get("password"), str)):
                raise ValueError("Invalid credentials form.")
            if kind == "manual_url" and answer is not None and not isinstance(answer, str):
                raise ValueError("Invalid RTSP URL.")
            try:
                self.pending_reply.put_nowait(answer)
            except queue.Full:
                raise ValueError("This prompt has already been answered.") from None
            self.prompt = None
            self.pending_reply = None
            self.phase = "working"

    def start_scan(self, mode: str, raw_cidr: str, confirmation: str) -> None:
        if mode not in ("scan", "scan_watch"):
            raise ValueError("Choose Scan only or Scan + Watch.")
        cidr, non_private = storage.validate_scope(raw_cidr.strip(), True)
        if confirmation != (cidr if non_private else "yes"):
            raise ValueError("Confirm authorization for the exact scan target before continuing.")

        def work():
            try:
                with storage.database() as db:
                    storage.add_scope(db, cidr, non_private)
                    scan_id, report, path = audit_scan.run_scan(
                        db, cidr, progress=self.message, cancel_event=self.cancel_event)
                with self.lock:
                    self.scan_id, self.report, self.report_path = scan_id, report, str(path)
                    self.phase = "scan_complete"
                    self.message_text = f"Scan complete: {len(report['hosts'])} live hosts."
            except scanner.ScanCancelled:
                with self.lock:
                    self.phase, self.error, self.message_text = "cancelled", None, "Scan cancelled."
            except (ValueError, OSError, scanner.ScanError) as exc:
                self._fail(str(exc))
            except Exception:
                self._fail("The scan failed unexpectedly.")

        with self.lock:
            if self.worker is not None and self.worker.is_alive():
                raise ValueError("Another operation is still running.")
            self.mode, self.phase = mode, "scanning"
            self.message_text, self.error = "Starting the scan", None
            self.report, self.scan_id, self.report_path = None, None, None
            self.cancel_event = threading.Event()
            self.worker = threading.Thread(target=work, daemon=True)
            self.worker.start()

    def cancel_scan(self) -> None:
        with self.lock:
            if self.phase not in ("scanning", "cancelling") or self.cancel_event is None:
                raise ValueError("No scan is running.")
            self.cancel_event.set()
            self.phase = "cancelling"
            self.message_text = "Stopping the scan…"

    def start_watch(self, ip: str) -> None:
        address = str(ipaddress.IPv4Address(ip))
        with self.lock:
            if self.mode != "scan_watch" or self.phase not in ("scan_complete", "watch_complete", "watch_failed"):
                raise ValueError("Run Scan + Watch before selecting a camera.")
            if self.worker is not None and self.worker.is_alive():
                raise ValueError("Another operation is still running.")
            if self.report is None or not any(host["ip"] == address and host.get("camera_candidate")
                                               for host in self.report["hosts"]):
                raise ValueError("Select a camera candidate from the current scan.")
            expected_scan_id = self.scan_id

        def work():
            try:
                with storage.database() as db:
                    latest = storage.latest_scan(db)
                    if latest is None or latest[0] != expected_scan_id:
                        raise ValueError("A newer scan exists. Run Scan + Watch again before opening a camera.")
                    result = watch.watch_camera(db, address, WebInteraction(self), confirm_each_time=True)
                with self.lock:
                    self.phase = "watch_complete" if result == 0 else "watch_failed"
                    if result != 0 and not self.error:
                        self.error = self.message_text
            except (ValueError, OSError, onvif.OnvifError, preview.PreviewError) as exc:
                self._fail(str(exc), "watch_failed")
            except Exception:
                self._fail("Camera preview failed unexpectedly.", "watch_failed")

        with self.lock:
            if self.worker is not None and self.worker.is_alive():
                raise ValueError("Another operation is still running.")
            self.phase, self.error = "working", None
            self.message_text = f"Preparing {address}"
            self.worker = threading.Thread(target=work, daemon=True)
            self.worker.start()

    def _fail(self, message: str, phase: str = "failed") -> None:
        with self.lock:
            self.phase, self.error, self.message_text = phase, message, message

    def close(self) -> None:
        with self.lock:
            if self.cancel_event is not None:
                self.cancel_event.set()
            if self.pending_reply is not None:
                try:
                    self.pending_reply.put_nowait(None)
                except queue.Full:
                    pass

    def ensure_idle(self) -> None:
        with self.lock:
            if self.worker is not None and self.worker.is_alive():
                raise ValueError("Finish or cancel the current camera action before closing the app.")


def _handler(session: Session):
    assets = files("camera_audit").joinpath("web")

    class Handler(BaseHTTPRequestHandler):
        server_version = "camera-audit"
        sys_version = ""

        def log_message(self, format, *args):
            pass

        def _host_ok(self) -> bool:
            return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

        def _authorized(self) -> bool:
            supplied = self.headers.get("X-Camera-Audit-Token", "")
            return secrets.compare_digest(supplied, session.token)

        def _send(self, status: int, data: bytes, content_type: str,
                  *, disposition: str | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            if content_type.startswith("text/html"):
                self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'")
            if disposition:
                self.send_header("Content-Disposition", disposition)
            self.end_headers()
            self.wfile.write(data)

        def _json(self, status: int, value) -> None:
            self._send(status, json.dumps(value, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def _request_json(self) -> dict:
            if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
                raise ValueError("Expected JSON input.")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise ValueError("Invalid request length.") from None
            if not 0 < length <= 16384:
                raise ValueError("Request is too large or empty.")
            try:
                value = json.loads(self.rfile.read(length))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ValueError("Invalid JSON input.") from None
            if not isinstance(value, dict):
                raise ValueError("Expected a JSON object.")
            return value

        def do_GET(self):
            if not self._host_ok():
                return self._json(HTTPStatus.FORBIDDEN, {"error": "Invalid host."})
            parsed = urlsplit(self.path)
            if self.path == "/":
                page = assets.joinpath("index.html").read_text(encoding="utf-8")
                page = page.replace("__SESSION_TOKEN__", session.token)
                return self._send(HTTPStatus.OK, page.encode(), "text/html; charset=utf-8")
            if self.path in ("/style.css", "/app.js"):
                name = self.path.removeprefix("/")
                content_type = "text/css; charset=utf-8" if name.endswith(".css") else "text/javascript; charset=utf-8"
                return self._send(HTTPStatus.OK, assets.joinpath(name).read_bytes(), content_type)
            if not self._authorized():
                return self._json(HTTPStatus.FORBIDDEN, {"error": "Session is not authorized."})
            try:
                if self.path == "/api/state":
                    return self._json(HTTPStatus.OK, session.snapshot())
                if parsed.path == "/api/results":
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    if set(query) - {"page", "candidates"} or any(len(values) != 1 for values in query.values()):
                        raise ValueError("Invalid results filter.")
                    raw_page = query.get("page", ["1"])[0]
                    if not raw_page.isdecimal():
                        raise ValueError("Page must be a positive integer.")
                    raw_candidates = query.get("candidates", ["0"])[0]
                    if raw_candidates not in ("0", "1"):
                        raise ValueError("Invalid results filter.")
                    return self._json(HTTPStatus.OK, session.results(int(raw_page), raw_candidates == "1"))
                if self.path == "/api/report":
                    report = session.report_json()
                    payload = (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode()
                    return self._send(HTTPStatus.OK, payload, "application/json; charset=utf-8",
                                      disposition=f'attachment; filename="scan-{session.scan_id}.json"')
            except ValueError as exc:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return self._json(HTTPStatus.NOT_FOUND, {"error": "Not found."})

        def do_POST(self):
            if not self._host_ok() or not self._authorized():
                return self._json(HTTPStatus.FORBIDDEN, {"error": "Session is not authorized."})
            origin = self.headers.get("Origin")
            if origin and origin != f"http://127.0.0.1:{self.server.server_port}":
                return self._json(HTTPStatus.FORBIDDEN, {"error": "Invalid origin."})
            try:
                data = self._request_json()
                if self.path == "/api/scan":
                    if not all(isinstance(data.get(name), str) for name in ("mode", "cidr", "confirmation")):
                        raise ValueError("Invalid scan form.")
                    session.start_scan(data["mode"], data["cidr"], data["confirmation"])
                elif self.path == "/api/target":
                    if not isinstance(data.get("cidr"), str):
                        raise ValueError("Enter an IPv4 CIDR.")
                    cidr, non_private = storage.validate_scope(data["cidr"].strip(), True)
                    return self._json(HTTPStatus.OK, {"cidr": cidr, "non_private": non_private})
                elif self.path == "/api/watch":
                    if not isinstance(data.get("ip"), str):
                        raise ValueError("Select a camera candidate.")
                    session.start_watch(data["ip"])
                elif self.path == "/api/respond":
                    if not isinstance(data.get("id"), str):
                        raise ValueError("Invalid prompt response.")
                    session.respond(data["id"], data.get("answer"))
                elif self.path == "/api/cancel":
                    session.cancel_scan()
                elif self.path == "/api/quit":
                    session.ensure_idle()
                    session.close()
                    self._json(HTTPStatus.OK, {"ok": True})
                    threading.Thread(target=self.server.shutdown, daemon=True).start()
                    return
                else:
                    return self._json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            except (ValueError, TypeError) as exc:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return self._json(HTTPStatus.ACCEPTED, {"ok": True})

    return Handler


def serve(*, open_browser: bool = True) -> int:
    """Run the private interface until the user closes it or presses Ctrl+C."""
    session = Session()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(session))
    server.daemon_threads = True
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"Camera Audit interface: {url}")
    print("Use the Close app button or press Ctrl+C to stop it.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        session.close()
        server.server_close()
    return 0

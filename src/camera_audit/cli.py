"""Command line interface for authorized camera audits."""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import shutil
import sys
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from . import audit_scan, local_network, onvif, preview, rtsp_discovery, scanner, storage, watch as watch_flow
from .nvd import enrich_hosts


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="camera-audit", description="Camera inventory and security audits on authorized networks")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Check local dependencies")
    scope = commands.add_parser("scope", help="Manage the authorized CIDR allowlist")
    scope_cmd = scope.add_subparsers(dest="scope_command", required=True)
    add = scope_cmd.add_parser("add")
    add.add_argument("cidr")
    add.add_argument("--non-private", action="store_true", help="Authorized lab CIDR outside private address space")
    scope_cmd.add_parser("list")
    remove = scope_cmd.add_parser("remove")
    remove.add_argument("cidr")
    scan = commands.add_parser("scan", help="Scan an authorized CIDR with Nmap")
    scan.add_argument("cidr", nargs="?")
    scan.add_argument("--local", action="store_true",
                      help="Detect and scan the default-route network; add it to scope after confirmation")
    scan.add_argument("--offline", action="store_true", help="Use only the local NVD cache")
    scan.add_argument("--json", type=Path, help="Report file; defaults to the application data directory")
    report = commands.add_parser("report", help="Show a saved scan")
    report.add_argument("scan_id", nargs="?", type=int)
    report.add_argument("--json", type=Path, help="Export the report as JSON")
    cameras = commands.add_parser("cameras", help="Camera candidates and approvals")
    cam_cmd = cameras.add_subparsers(dest="camera_command", required=True)
    cam_cmd.add_parser("candidates")
    cam_cmd.add_parser("list")
    approve = cam_cmd.add_parser("approve")
    approve.add_argument("ip")
    approve.add_argument("--rtsp-url")
    approve.add_argument("--onvif-url")
    approve.add_argument("--username")
    credentials = cam_cmd.add_parser("credentials")
    credentials.add_argument("ip")
    credentials.add_argument("--username", required=True)
    inspect = cam_cmd.add_parser("inspect", help="Inspect an authorized camera without opening video")
    inspect.add_argument("ip")
    inspect.add_argument("--rtsp-path", action="append", dest="rtsp_paths", metavar="PATH",
                         help="RTSP path to test instead of the default path list; repeatable")
    preview_parser = commands.add_parser("preview", help="Open the live stream from an approved camera")
    preview_parser.add_argument("ip")
    watch_parser = commands.add_parser("watch", help="Select an authorized camera and open a live preview")
    watch_parser.add_argument("ip", nargs="?")
    watch_parser.add_argument("--rtsp-path", action="append", dest="rtsp_paths", metavar="PATH",
                              help="RTSP path to test instead of the default path list; repeatable")
    return parser


def _doctor() -> int:
    print(f"Nmap: {shutil.which('nmap') or 'not found'}")
    print(f"ffplay: {shutil.which('ffplay') or 'not found'}")
    try:
        import av
        print(f"PyAV: {av.__version__}")
    except ImportError:
        print("PyAV: not installed (reinstall camera-audit to enable preview)")
    try:
        print(f"Credential store: {type(preview._keyring().get_keyring()).__module__}")
    except preview.PreviewError as exc:
        print(f"Credential store: {exc}")
    print(f"Data directory: {storage.data_dir()}")
    return 0


def _scope(args, db) -> int:
    if args.scope_command == "add":
        cidr, non_private = storage.add_scope(db, args.cidr, args.non_private)
        print(f"Added to scope: {cidr}" + (" (non-private lab range)" if non_private else ""))
    elif args.scope_command == "list":
        for row in db.execute("SELECT cidr, non_private FROM scopes ORDER BY cidr"):
            print(row["cidr"] + ("  [non-private]" if row["non_private"] else ""))
    else:
        cidr = str(ipaddress.ip_network(args.cidr, strict=True))
        db.execute("DELETE FROM scopes WHERE cidr = ?", (cidr,))
        db.commit()
        print(f"Removed from scope: {cidr}")
    return 0


def _confirm_scan(cidr: str, non_private: bool, input_fn=None) -> bool:
    input_fn = input if input_fn is None else input_fn
    print(f"Target: {cidr}")
    print("Profile: live host discovery; top 1,000 TCP ports; lightweight service/version detection (-T3).")
    print("Confirm that you are authorized to scan this range.")
    if non_private:
        return input_fn(f"Type the exact CIDR to continue ({cidr}): ").strip() == cidr
    return input_fn("Type 'yes' to start the scan: ").strip().lower() == "yes"


def _summary(report: dict) -> None:
    print(f"Scan: {report['cidr']} | {report['created_at']} | {len(report['hosts'])} live hosts")
    for host in report["hosts"]:
        label = " [CAMERA CANDIDATE]" if host["camera_candidate"] else ""
        ports = ", ".join(f"{port['port']}/{port['protocol']} {port.get('service') or '?'}" for port in host["ports"])
        print(f"{host['ip']}{label} | {ports or 'no open TCP ports found'}")
        if host["camera_candidate"]:
            print("  Evidence: " + "; ".join(host["camera_evidence"]))
        for finding in host.get("vulnerabilities", []):
            print(f"  {finding['id']} — potential impact; CVSS {finding.get('score') or '?'}; {finding['url']}")
        if host.get("nvd_status") in ("lookup_unavailable", "offline_unavailable", "stale_cache"):
            print(f"  NVD status: {host['nvd_status']}")


def _scan(args, db) -> int:
    if args.local and args.cidr:
        raise ValueError("Use either --local or an explicit CIDR, not both.")
    if args.local:
        detected = local_network.detect()
        cidr, non_private = storage.validate_scope(str(detected.network), False)
        print(f"Detected local network: {detected.address} on {detected.interface} ({cidr})")
    else:
        if not args.cidr:
            raise ValueError("Provide an authorized CIDR or use --local to detect the default-route network.")
        scope = storage.get_scope(db, args.cidr)
        cidr, non_private = scope["cidr"], bool(scope["non_private"])
    if not _confirm_scan(cidr, non_private):
        print("Scan cancelled.")
        return 1
    if args.local:
        storage.add_scope(db, cidr, False)
        print(f"Added detected network to scope: {cidr}")
    print("Running Nmap host discovery and service scan…", flush=True)
    scan_id, report, destination = audit_scan.run_scan(
        db, cidr, offline=args.offline, destination=args.json,
        scan_fn=scanner.scan, enrich_fn=enrich_hosts)
    _summary(report)
    print(f"JSON report: {destination}")
    return 0


def _report(args, db) -> int:
    report = storage.scan_by_id(db, args.scan_id) if args.scan_id else None
    if report is None and args.scan_id is None:
        latest = storage.latest_scan(db)
        report = latest[1] if latest else None
    if report is None:
        raise ValueError("Scan report not found.")
    _summary(report)
    if args.json:
        print(f"JSON report: {storage.export_report(report, args.json)}")
    return 0


def _cameras(args, db) -> int:
    if args.camera_command == "inspect":
        return watch_flow.inspect(db, args.ip, args.rtsp_paths or rtsp_discovery.DEFAULT_PATHS)
    if args.camera_command == "candidates":
        latest = storage.latest_scan(db)
        if latest is None:
            raise ValueError("Run a scan first.")
        storage.get_scope(db, latest[1]["cidr"])
        for host in latest[1]["hosts"]:
            if host["camera_candidate"]:
                print(f"{host['ip']}: {', '.join(host['camera_evidence'])}")
        return 0
    if args.camera_command == "list":
        for row in db.execute("SELECT * FROM cameras ORDER BY ip"):
            rtsp_label = "[stored securely]" if row["rtsp_url_secret"] else "[redacted]" if row["rtsp_url"] and urlsplit(row["rtsp_url"]).query else row["rtsp_url"] or "-"
            onvif_label = "[redacted]" if row["onvif_url"] and urlsplit(row["onvif_url"]).query else row["onvif_url"] or "-"
            print(f"{row['ip']} | RTSP: {rtsp_label} | ONVIF: {onvif_label} | username: {row['username'] or '-'}")
        return 0
    ip = str(ipaddress.ip_address(args.ip))
    if args.camera_command == "credentials":
        scan_id, host = storage.authorized_candidate(db, ip)
        device_key, _, identity_aux = storage.host_identity(host, scan_id)
        camera = storage.get_camera(db, ip)
        if camera is None:
            connection = storage.get_connection(db, device_key)
            if (connection is None or connection["approved_ip"] != ip
                    or connection["identity_aux"] != identity_aux):
                raise ValueError("Camera has not been approved.")
            password = getpass.getpass("Camera password (stored in the system credential manager): ")
            preview.save_password(device_key, password)
            record = dict(connection)
            record.update(username=args.username, auth_required=1)
            storage.save_connection(db, record)
            print("Credentials saved.")
            return 0
        if camera["device_key"] != device_key or camera["identity_aux"] != identity_aux:
            raise ValueError("Device identity could not be verified. Approve this camera again.")
        password = getpass.getpass("Camera password (stored in the system credential manager): ")
        preview.save_password(device_key, password)
        storage.save_camera(db, ip, camera["rtsp_url"], camera["onvif_url"], args.username,
                            device_key, identity_aux, scan_id, bool(camera["rtsp_url_secret"]))
        print("Credentials saved.")
        return 0
    scan_id, host = storage.authorized_candidate(db, ip)
    device_key, _, identity_aux = storage.host_identity(host, scan_id)
    rtsp_url = args.rtsp_url
    onvif_url = args.onvif_url or host.get("onvif_url")
    if rtsp_url:
        onvif.validate_device_url(rtsp_url, ip, ("rtsp", "rtsps"))
    if onvif_url:
        onvif.validate_device_url(onvif_url, ip, ("http", "https"))
        if urlsplit(onvif_url).query:
            raise ValueError("ONVIF URLs with query parameters cannot be saved; use a credential-free endpoint.")
    if not rtsp_url and not onvif_url:
        raise ValueError("Provide --rtsp-url or ensure an ONVIF endpoint has been discovered.")
    if args.username:
        password = getpass.getpass("Camera password (stored in the system credential manager): ")
        preview.save_password(device_key, password)
    secret_url = bool(rtsp_url and urlsplit(rtsp_url).query)
    if secret_url:
        preview.save_stream_url(device_key, rtsp_url)
    storage.save_camera(db, ip, None if secret_url else rtsp_url, onvif_url, args.username,
                        device_key, identity_aux, scan_id, secret_url)
    print(f"Camera approved: {ip}")
    return 0


def _preview(args, db) -> int:
    ip = str(ipaddress.ip_address(args.ip))
    scan_id, host = storage.authorized_candidate(db, ip)
    device_key, identity_kind, identity_aux = storage.host_identity(host, scan_id)
    camera = storage.get_camera(db, ip)
    if camera is None:
        raise ValueError("Camera has not been approved.")
    if (camera["device_key"] != device_key or camera["identity_aux"] != identity_aux
            or (identity_kind == "scan" and camera["approval_scan_id"] != scan_id)):
        raise ValueError("Device identity could not be verified. Approve this camera again.")
    password = preview.load_password(device_key) if camera["username"] else None
    if camera["username"] and password is None:
        raise preview.PreviewError("Password not found in the credential store; use 'cameras credentials'.")
    uri = camera["rtsp_url"] or (preview.load_stream_url(device_key) if camera["rtsp_url_secret"] else None)
    if not uri:
        if not camera["onvif_url"]:
            raise ValueError("No usable stream URL is saved. Approve the camera again or use watch.")
        uri = onvif.get_stream_uri(camera["onvif_url"], ip, camera["username"], password)
    print("Opening live preview. Press Ctrl+C to close it.")
    if preview.play(uri, ip, camera["username"], password):
        return 0
    raise preview.PreviewError("Preview ended before a video frame was received.")


def _watch(args, db) -> int:
    scan_local = lambda: _scan(argparse.Namespace(local=True, cidr=None, offline=False, json=None), db)
    return watch_flow.run(db, args.ip, args.rtsp_paths or rtsp_discovery.DEFAULT_PATHS, scan_local)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        from . import web_ui
        return web_ui.serve()
    args = _parser().parse_args(argv)
    try:
        if args.command == "doctor":
            return _doctor()
        with storage.database() as db:
            if args.command == "scope":
                return _scope(args, db)
            if args.command == "scan":
                return _scan(args, db)
            if args.command == "report":
                return _report(args, db)
            if args.command == "cameras":
                return _cameras(args, db)
            if args.command == "preview":
                return _preview(args, db)
            if args.command == "watch":
                return _watch(args, db)
    except (ValueError, EOFError, OSError, scanner.ScanError, onvif.OnvifError, preview.PreviewError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

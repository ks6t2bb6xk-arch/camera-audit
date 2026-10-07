"""Interactive, authorized camera stream discovery and preview."""

from __future__ import annotations

import getpass
import ipaddress
from typing import Protocol
from urllib.parse import urlsplit

from . import onvif, preview, rtsp_discovery, storage


class Cancelled(Exception):
    pass


class Interaction(Protocol):
    def confirm(self, message: str) -> bool: ...
    def choose(self, message: str, options: list[str]) -> int: ...
    def credentials(self, suggested: str | None) -> tuple[str, str]: ...
    def manual_url(self, ip: str) -> str | None: ...
    def notice(self, message: str) -> None: ...


def _yes(prompt: str) -> bool:
    return input(prompt).strip().lower() == "yes"


def _choice(count: int, prompt: str) -> int:
    while True:
        answer = input(prompt).strip().lower()
        if answer in ("", "0", "q", "quit"):
            raise Cancelled
        if answer.isdecimal() and 1 <= int(answer) <= count:
            return int(answer) - 1
        print(f"Enter a number from 1 to {count}, or 0 to cancel.")


class ConsoleInteraction:
    def confirm(self, message: str) -> bool:
        return _yes(message + " Type 'yes': ")

    def choose(self, message: str, options: list[str]) -> int:
        print(message)
        for index, option in enumerate(options, 1):
            print(f"  {index}. {option}")
        return _choice(len(options), "Select a number (0 to cancel): ")

    def credentials(self, suggested: str | None) -> tuple[str, str]:
        return _credentials({"username": suggested})

    def manual_url(self, ip: str) -> str | None:
        return _manual_url(ip)

    def notice(self, message: str) -> None:
        print(message)


def _rtsp_ports(host: dict) -> list[int]:
    return list(dict.fromkeys(port["port"] for port in host.get("ports", [])
                              if "rtsp" in (port.get("service") or "").lower()
                              or port["port"] in (554, 8554)))[:3]


def _fresh_record(host: dict, scan_id: int, db) -> dict:
    key, kind, aux = storage.host_identity(host, scan_id)
    existing = storage.get_connection(db, key)
    if existing and existing["identity_aux"] == aux:
        record = dict(existing)
        if record["last_seen_ip"] != host["ip"]:
            record.update(rtsp_url=None, rtsp_url_secret=0, onvif_url=None, approved_ip=None,
                          approved_at=None, verification_status="unverified")
    else:
        record = {"device_key": key, "identity_kind": kind, "identity_aux": aux,
                  "last_seen_ip": host["ip"], "rtsp_url": None, "rtsp_url_secret": 0,
                  "onvif_url": None, "profile_token": None, "username": None,
                  "auth_required": 0, "approved_ip": None, "approved_at": None,
                  "last_success_at": None, "verification_status": "unverified"}
        legacy = storage.get_camera(db, host["ip"])
        if legacy and legacy["device_key"] == key and legacy["identity_aux"] == aux:
            record.update(approved_ip=host["ip"], approved_at=legacy["approved_at"],
                          rtsp_url=legacy["rtsp_url"] if legacy["rtsp_url"] and not urlsplit(legacy["rtsp_url"]).query else None,
                          rtsp_url_secret=int(bool(legacy["rtsp_url_secret"])),
                          onvif_url=legacy["onvif_url"] if legacy["onvif_url"] and not urlsplit(legacy["onvif_url"]).query else None,
                          username=legacy["username"])
    record["last_seen_ip"] = host["ip"]
    if host.get("onvif_url") and not urlsplit(host["onvif_url"]).query:
        record["onvif_url"] = host["onvif_url"]
    return record


def _saved_url(record: dict) -> str | None:
    if record["rtsp_url_secret"]:
        return preview.load_stream_url(record["device_key"])
    return record["rtsp_url"]


def _saved_credentials(record: dict) -> tuple[str | None, str | None]:
    username = record.get("username")
    if not username:
        return None, None
    return username, preview.load_password(record["device_key"])


def _status(host: dict, scan_id: int, db) -> str:
    record = _fresh_record(host, scan_id, db)
    if record["approved_ip"] == host["ip"] and record["auth_required"] and not (record["rtsp_url"] or record["rtsp_url_secret"]):
        return "Authentication Required"
    if record["approved_ip"] == host["ip"] and (record["rtsp_url"] or record["rtsp_url_secret"]):
        if record["auth_required"]:
            try:
                if not _saved_credentials(record)[1]:
                    return "Authentication Required"
            except preview.PreviewError:
                return "Authentication Required"
        if record["verification_status"] in ("sdp_verified", "preview_opened"):
            return "Ready"
    if record["onvif_url"] or _rtsp_ports(host):
        return "Discovery Required"
    return "Unavailable"


def _show_candidate(host: dict, scan_id: int, db, number: int | None = None) -> None:
    services = ", ".join(f"{port['port']}/{port.get('service') or '?'}" for port in host.get("ports", [])) or "none"
    rtsp = ", ".join(map(str, _rtsp_ports(host))) or "none"
    vendor = host.get("mac_vendor") or "unknown"
    prefix = f"{number}. " if number is not None else ""
    print(f"{prefix}{host['ip']} | vendor: {vendor} | services: {services} | RTSP ports: {rtsp} | {_status(host, scan_id, db)}")


def _credentials(record: dict) -> tuple[str, str]:
    suggested = record.get("username") or ""
    prompt = f"Username [{suggested}]: " if suggested else "Username (blank cancels): "
    username = input(prompt).strip() or suggested
    if not username:
        raise Cancelled
    password = getpass.getpass("Camera password: ")
    if not password:
        raise Cancelled
    return username, password


def _select_profile(profiles: list[dict], interaction: Interaction) -> dict:
    if len(profiles) == 1:
        return profiles[0]
    return profiles[interaction.choose("Select an ONVIF media profile:",
                                       [profile["name"] for profile in profiles])]


def _onvif_stream(host: dict, record: dict, interaction: Interaction) -> tuple[str, str, str | None, str | None] | None:
    endpoint = record["onvif_url"]
    if not endpoint:
        return None
    username, password = _saved_credentials(record)
    try:
        profiles = onvif.list_profiles(endpoint, host["ip"], username, password)
    except onvif.OnvifAuthRequired:
        interaction.notice("ONVIF authentication is required.")
        record["auth_required"] = 1
        record["verification_status"] = "auth_required"
        username, password = interaction.credentials(record.get("username"))
        try:
            profiles = onvif.list_profiles(endpoint, host["ip"], username, password)
        except (onvif.OnvifError, ValueError) as exc:
            interaction.notice(f"ONVIF authentication or profile discovery failed ({exc}); trying RTSP discovery.")
            return None
    except (onvif.OnvifError, ValueError) as exc:
        interaction.notice(f"ONVIF discovery failed ({exc}); trying RTSP discovery.")
        return None
    profile = _select_profile(profiles, interaction)
    try:
        uri = onvif.stream_uri_for_profile(profile, host["ip"], username, password)
    except (onvif.OnvifError, ValueError):
        interaction.notice("ONVIF did not provide a usable stream URI; trying RTSP discovery.")
        return None
    return uri, profile["token"], username, password


def _rtsp_stream(host: dict, record: dict, paths: tuple[str, ...] | list[str],
                 interaction: Interaction) -> tuple[str, str | None, str | None, bool] | None:
    ports = _rtsp_ports(host)
    if not ports:
        return None
    results = rtsp_discovery.discover(host["ip"], ports, paths)
    valid = [result for result in results if result.status == "valid"]
    if valid:
        if len(valid) > 1:
            selected = valid[interaction.choose("Select a verified RTSP endpoint:",
                                                [result.url for result in valid])]
        else:
            selected = valid[0]
        return selected.url, None, None, False
    auth_candidates = [result for result in results if result.status == "auth_required"]
    if not auth_candidates:
        if results:
            details = "; ".join(
                f"{urlsplit(result.url).port}{urlsplit(result.url).path}: {result.detail or result.status}"
                for result in results
            )
            interaction.notice(f"RTSP endpoint checks did not find a playable stream: {details}")
        return None
    record["auth_required"] = 1
    record["verification_status"] = "auth_required"
    interaction.notice("RTSP endpoints requested authentication; their stream paths are not yet verified.")
    selected = auth_candidates[interaction.choose("Select one endpoint to authenticate:",
                                                    [result.url for result in auth_candidates])]
    username, password = _saved_credentials(record)
    if not username or password is None:
        username, password = interaction.credentials(record.get("username"))
    basic = "Basic" in selected.detail
    allow_basic = interaction.confirm("Basic authentication sends credentials over plaintext RTSP. Allow this one attempt?") if basic else False
    if basic and not allow_basic:
        raise Cancelled
    parsed = urlsplit(selected.url)
    verified = rtsp_discovery.probe(host["ip"], parsed.port, parsed.path.lstrip("/"),
                                    username, password, allow_basic)
    if verified.status == "valid":
        return verified.url, username, password, True
    interaction.notice(f"The selected RTSP path could not be verified with those credentials ({verified.detail or verified.status}).")
    return None


def _manual_url(ip: str) -> str | None:
    value = input("Enter an RTSP URL for this camera, or press Enter to cancel: ").strip()
    if not value:
        return None
    return onvif.validate_device_url(value, ip, ("rtsp", "rtsps"))


def _remember(db, record: dict, url: str, profile_token: str | None,
              username: str | None, password: str | None, status: str) -> None:
    ip = record["last_seen_ip"]
    onvif.validate_device_url(url, ip, ("rtsp", "rtsps"))
    if urlsplit(url).query:
        preview.save_stream_url(record["device_key"], url)
        record["rtsp_url"] = None
        record["rtsp_url_secret"] = 1
    else:
        record["rtsp_url"] = url
        record["rtsp_url_secret"] = 0
    if username and password is not None:
        preview.save_password(record["device_key"], password)
    record.update(profile_token=profile_token, username=username,
                  auth_required=int(bool(username)), verification_status=status)
    storage.save_connection(db, record)


def _prepare(db, scan_id: int, host: dict,
             paths: tuple[str, ...] | list[str], inspect_only: bool,
             interaction: Interaction, confirm_each_time: bool = False) -> tuple[dict, str | None, str | None, str | None]:
    record = _fresh_record(host, scan_id, db)
    if record["approved_ip"] != host["ip"] or confirm_each_time:
        if not interaction.confirm(f"Authorize camera stream access for {host['ip']}?"):
            raise Cancelled
        record["approved_ip"] = host["ip"]
        record["approved_at"] = storage.utc_now()
        storage.save_connection(db, record)
    url = _saved_url(record)
    username, password = _saved_credentials(record)
    if url:
        onvif.validate_device_url(url, host["ip"], ("rtsp", "rtsps"))
        interaction.notice("Using the saved stream endpoint.")
        return record, url, username, password
    discovered = _onvif_stream(host, record, interaction)
    if discovered:
        url, profile, username, password = discovered
        _remember(db, record, url, profile, username, password, "discovered")
        interaction.notice("ONVIF provided a stream endpoint. Playback has not been verified yet.")
        return record, url, username, password
    rtsp = _rtsp_stream(host, record, paths, interaction)
    if rtsp:
        url, username, password, authenticated = rtsp
        _remember(db, record, url, None, username, password, "sdp_verified")
        interaction.notice("RTSP returned valid video SDP. Playback has not been verified yet.")
        return record, url, username, password
    if record["verification_status"] == "auth_required":
        storage.save_connection(db, record)
    interaction.notice("Automatic stream discovery did not verify a playable endpoint.")
    if inspect_only:
        return record, None, None, None
    url = interaction.manual_url(host["ip"])
    if url:
        onvif.validate_device_url(url, host["ip"], ("rtsp", "rtsps"))
    return record, url, None, None


def inspect(db, ip: str, paths: tuple[str, ...] | list[str] = rtsp_discovery.DEFAULT_PATHS) -> int:
    address = str(ipaddress.IPv4Address(ip))
    scan_id, host = storage.authorized_candidate(db, address)
    _show_candidate(host, scan_id, db)
    record = _fresh_record(host, scan_id, db)
    print(f"ONVIF endpoint: {'found' if record['onvif_url'] else 'not found'}")
    print(f"Verification: {record['verification_status']}")
    print(f"Saved media profile: {record['profile_token'] or 'none'}")
    print(f"Authentication: {'required' if record['auth_required'] else 'not observed'}")
    if record["rtsp_url_secret"]:
        print("Saved stream URL: stored securely")
    elif record["rtsp_url"]:
        print(f"Saved stream URL: {record['rtsp_url']}")
    print(f"Last successful preview: {record['last_success_at'] or 'none'}")
    if not _yes("Run bounded stream discovery for this camera? Type 'yes': "):
        return 0
    try:
        _prepare(db, scan_id, host, paths, True, ConsoleInteraction())
    except Cancelled:
        print("Cancelled.")
    return 0


def watch_camera(db, ip: str, interaction: Interaction,
                 paths: tuple[str, ...] | list[str] = rtsp_discovery.DEFAULT_PATHS,
                 confirm_each_time: bool = False) -> int:
    """Use the same authorized camera workflow from either user interface."""
    address = str(ipaddress.IPv4Address(ip))
    scan_id, host = storage.authorized_candidate(db, address)
    try:
        record, url, username, password = _prepare(db, scan_id, host, paths, False,
                                                    interaction, confirm_each_time)
        if not url:
            interaction.notice("No stream URL was selected.")
            return 1
        if record["auth_required"] and (not username or password is None):
            username, password = interaction.credentials(record.get("username"))
        if not interaction.confirm("Open the live preview?"):
            interaction.notice("Preview cancelled.")
            return 0
        try:
            opened = preview.play(url, host["ip"], username, password)
        except preview.PreviewError as exc:
            interaction.notice(f"Preview failed: {exc}")
            if not interaction.confirm("Update credentials and retry once?"):
                return 1
            username, password = interaction.credentials(record.get("username"))
            opened = preview.play(url, host["ip"], username, password)
        if not opened:
            interaction.notice("Preview ended before a video frame was received.")
            return 1
        _remember(db, record, url, record["profile_token"], username, password, "preview_opened")
        record["last_success_at"] = storage.utc_now()
        storage.save_connection(db, record)
        interaction.notice("Preview closed. Successful connection saved.")
        return 0
    except Cancelled:
        interaction.notice("Cancelled.")
        return 0


def run(db, ip: str | None = None,
        paths: tuple[str, ...] | list[str] = rtsp_discovery.DEFAULT_PATHS,
        scan_local=None) -> int:
    latest = storage.latest_scan(db)
    if latest is None:
        print("No saved scan was found.")
        if scan_local is None or not _yes("Run a local network scan now? Type 'yes': "):
            return 1
        if scan_local() != 0:
            return 1
        latest = storage.latest_scan(db)
    if latest is None:
        return 1
    scan_id, report = latest
    storage.get_scope(db, report["cidr"])
    if ip is not None:
        address = str(ipaddress.IPv4Address(ip))
        scan_id, host = storage.authorized_candidate(db, address)
    else:
        candidates = [host for host in report["hosts"] if host.get("camera_candidate")]
        if not candidates:
            print("No camera candidates were found in the latest scan.")
            return 1
        print("Camera candidates:")
        for index, candidate in enumerate(candidates, 1):
            _show_candidate(candidate, scan_id, db, index)
        try:
            host = candidates[_choice(len(candidates), "Select a camera (0 to cancel): ")]
        except Cancelled:
            print("Cancelled.")
            return 0
        scan_id, host = storage.authorized_candidate(db, host["ip"])
    _show_candidate(host, scan_id, db)
    return watch_camera(db, host["ip"], ConsoleInteraction(), paths)

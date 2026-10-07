"""Local state. No state from the earlier alert application is read."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


PRIVATE_LAN = tuple(ipaddress.ip_network(value) for value in
                    ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def data_dir() -> Path:
    override = os.environ.get("CAMERA_AUDIT_DATA_DIR")
    if override:
        return Path(override).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "camera-audit"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "camera-audit"


def private_dir(path: Path) -> None:
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path, 0o700)
    elif not path.is_dir():
        raise ValueError(f"Expected a directory: {path}")


def database() -> sqlite3.Connection:
    base = data_dir()
    private_dir(base)
    target = base / "camera-audit.sqlite3"
    connection = sqlite3.connect(target)
    os.chmod(target, 0o600)
    connection.row_factory = sqlite3.Row
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS scopes (
            cidr TEXT PRIMARY KEY,
            non_private INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            cidr TEXT NOT NULL,
            report_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cameras (
            ip TEXT PRIMARY KEY,
            approved_at TEXT NOT NULL,
            rtsp_url TEXT,
            onvif_url TEXT,
            username TEXT
        );
        CREATE TABLE IF NOT EXISTS camera_connections (
            device_key TEXT PRIMARY KEY,
            identity_kind TEXT NOT NULL,
            identity_aux TEXT,
            last_seen_ip TEXT NOT NULL,
            rtsp_url TEXT,
            rtsp_url_secret INTEGER NOT NULL DEFAULT 0,
            onvif_url TEXT,
            profile_token TEXT,
            username TEXT,
            auth_required INTEGER NOT NULL DEFAULT 0,
            approved_ip TEXT,
            approved_at TEXT,
            last_success_at TEXT,
            verification_status TEXT NOT NULL DEFAULT 'unverified'
        );
        CREATE TABLE IF NOT EXISTS nvd_cache (
            cpe TEXT PRIMARY KEY,
            fetched_at TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
    """)
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(cameras)")}
    for name, declaration in (
        ("device_key", "TEXT"),
        ("identity_aux", "TEXT"),
        ("approval_scan_id", "INTEGER"),
        ("rtsp_url_secret", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if name not in columns:
            connection.execute(f"ALTER TABLE cameras ADD COLUMN {name} {declaration}")
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version < 2:
        connection.execute("PRAGMA user_version = 2")
    connection.commit()
    return connection


def validate_scope(cidr: str, allow_non_private: bool) -> tuple[str, bool]:
    network = ipaddress.ip_network(cidr, strict=True)
    if network.version != 4:
        raise ValueError("This version supports IPv4 CIDR scans only.")
    is_private = any(network.subnet_of(block) for block in PRIVATE_LAN)
    if not is_private and not allow_non_private:
        raise ValueError("Use --non-private for networks outside private address space.")
    if network.num_addresses > 4096:
        raise ValueError("Each scope can contain at most 4,096 addresses; split it into smaller CIDRs.")
    canonical = str(network)
    return canonical, not is_private


def add_scope(db: sqlite3.Connection, cidr: str, allow_non_private: bool) -> tuple[str, bool]:
    canonical, non_private = validate_scope(cidr, allow_non_private)
    db.execute("INSERT OR REPLACE INTO scopes(cidr, non_private) VALUES (?, ?)",
               (canonical, int(non_private)))
    db.commit()
    return canonical, non_private


def get_scope(db: sqlite3.Connection, cidr: str) -> sqlite3.Row:
    canonical = str(ipaddress.ip_network(cidr, strict=True))
    row = db.execute("SELECT cidr, non_private FROM scopes WHERE cidr = ?", (canonical,)).fetchone()
    if row is None:
        raise ValueError("CIDR is not in the allowlist. Add it first with 'camera-audit scope add CIDR'.")
    return row


def save_scan(db: sqlite3.Connection, report: dict) -> int:
    cursor = db.execute("INSERT INTO scans(created_at, cidr, report_json) VALUES (?, ?, ?)",
                        (report["created_at"], report["cidr"], json.dumps(report, ensure_ascii=False)))
    db.commit()
    return int(cursor.lastrowid)


def latest_scan(db: sqlite3.Connection) -> tuple[int, dict] | None:
    row = db.execute("SELECT id, report_json FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return (row["id"], json.loads(row["report_json"])) if row else None


def authorized_candidate(db: sqlite3.Connection, ip: str) -> tuple[int, dict]:
    address = ipaddress.ip_address(ip)
    latest = latest_scan(db)
    if latest is None:
        raise ValueError("Run a scan first.")
    scan_id, report = latest
    network = ipaddress.ip_network(report["cidr"], strict=True)
    get_scope(db, str(network))
    if address not in network:
        raise ValueError("Device is outside the authorized scan scope.")
    host = next((item for item in report["hosts"] if item["ip"] == str(address)), None)
    if host is None or not host.get("camera_candidate"):
        raise ValueError("Device is not a camera candidate in the latest authorized scan.")
    return scan_id, host


def host_identity(host: dict, scan_id: int) -> tuple[str, str, str | None]:
    mac = host.get("mac") or ""
    normalized_mac = mac.upper() if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac) else None
    onvif_uuid = host.get("onvif_uuid")
    if onvif_uuid:
        suffix = f":mac:{normalized_mac}" if normalized_mac else ""
        return f"onvif:{onvif_uuid}{suffix}", "onvif", normalized_mac
    if normalized_mac:
        return f"mac:{normalized_mac}", "mac", None
    return f"scan:{scan_id}:ip:{host['ip']}", "scan", None


def scan_by_id(db: sqlite3.Connection, scan_id: int) -> dict | None:
    row = db.execute("SELECT report_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return json.loads(row["report_json"]) if row else None


def save_camera(db: sqlite3.Connection, ip: str, rtsp_url: str | None,
                onvif_url: str | None, username: str | None,
                device_key: str | None = None, identity_aux: str | None = None,
                approval_scan_id: int | None = None, rtsp_url_secret: bool = False) -> None:
    db.execute("""INSERT INTO cameras(ip, approved_at, rtsp_url, onvif_url, username,
                  device_key, identity_aux, approval_scan_id, rtsp_url_secret)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                  ON CONFLICT(ip) DO UPDATE SET approved_at=excluded.approved_at,
                  rtsp_url=excluded.rtsp_url, onvif_url=excluded.onvif_url,
                  username=excluded.username, device_key=excluded.device_key,
                  identity_aux=excluded.identity_aux,
                  approval_scan_id=excluded.approval_scan_id,
                  rtsp_url_secret=excluded.rtsp_url_secret""",
               (ip, utc_now(), rtsp_url, onvif_url, username,
                device_key, identity_aux, approval_scan_id, int(rtsp_url_secret)))
    db.commit()


def get_camera(db: sqlite3.Connection, ip: str) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM cameras WHERE ip = ?", (ip,)).fetchone()


def get_connection(db: sqlite3.Connection, device_key: str) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM camera_connections WHERE device_key = ?", (device_key,)).fetchone()


def save_connection(db: sqlite3.Connection, record: dict) -> None:
    columns = ("device_key", "identity_kind", "identity_aux", "last_seen_ip", "rtsp_url",
               "rtsp_url_secret", "onvif_url", "profile_token", "username", "auth_required",
               "approved_ip", "approved_at", "last_success_at", "verification_status")
    values = tuple(record.get(column) for column in columns)
    db.execute("""INSERT INTO camera_connections
                  (device_key, identity_kind, identity_aux, last_seen_ip, rtsp_url,
                   rtsp_url_secret, onvif_url, profile_token, username, auth_required,
                   approved_ip, approved_at, last_success_at, verification_status)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                  ON CONFLICT(device_key) DO UPDATE SET
                   identity_kind=excluded.identity_kind, identity_aux=excluded.identity_aux,
                   last_seen_ip=excluded.last_seen_ip, rtsp_url=excluded.rtsp_url,
                   rtsp_url_secret=excluded.rtsp_url_secret, onvif_url=excluded.onvif_url,
                   profile_token=excluded.profile_token, username=excluded.username,
                   auth_required=excluded.auth_required, approved_ip=excluded.approved_ip,
                   approved_at=excluded.approved_at, last_success_at=excluded.last_success_at,
                   verification_status=excluded.verification_status""", values)
    db.commit()


def export_report(report: dict, destination: Path) -> Path:
    private_dir(destination.parent)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)
        file.write("\n")
    return destination

"""Local state. No state from the earlier alert application is read."""

from __future__ import annotations

import ipaddress
import json
import os
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
        raise ValueError(f"Dizin bekleniyor: {path}")


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
        CREATE TABLE IF NOT EXISTS nvd_cache (
            cpe TEXT PRIMARY KEY,
            fetched_at TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
    """)
    return connection


def add_scope(db: sqlite3.Connection, cidr: str, allow_non_private: bool) -> tuple[str, bool]:
    network = ipaddress.ip_network(cidr, strict=True)
    if network.version != 4:
        raise ValueError("Bu sürüm yalnızca IPv4 CIDR taramasını destekler.")
    is_private = any(network.subnet_of(block) for block in PRIVATE_LAN)
    if not is_private and not allow_non_private:
        raise ValueError("Özel olmayan ağ için --non-private gerekli.")
    if network.num_addresses > 4096:
        raise ValueError("Bir kapsam en fazla 4096 adres içerebilir; daha küçük CIDR'lere bölün.")
    canonical = str(network)
    db.execute("INSERT OR REPLACE INTO scopes(cidr, non_private) VALUES (?, ?)",
               (canonical, int(not is_private)))
    db.commit()
    return canonical, not is_private


def get_scope(db: sqlite3.Connection, cidr: str) -> sqlite3.Row:
    canonical = str(ipaddress.ip_network(cidr, strict=True))
    row = db.execute("SELECT cidr, non_private FROM scopes WHERE cidr = ?", (canonical,)).fetchone()
    if row is None:
        raise ValueError("CIDR allowlist'te yok. Önce 'camera-audit scope add CIDR' kullanın.")
    return row


def save_scan(db: sqlite3.Connection, report: dict) -> int:
    cursor = db.execute("INSERT INTO scans(created_at, cidr, report_json) VALUES (?, ?, ?)",
                        (report["created_at"], report["cidr"], json.dumps(report, ensure_ascii=False)))
    db.commit()
    return int(cursor.lastrowid)


def latest_scan(db: sqlite3.Connection) -> tuple[int, dict] | None:
    row = db.execute("SELECT id, report_json FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return (row["id"], json.loads(row["report_json"])) if row else None


def scan_by_id(db: sqlite3.Connection, scan_id: int) -> dict | None:
    row = db.execute("SELECT report_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return json.loads(row["report_json"]) if row else None


def save_camera(db: sqlite3.Connection, ip: str, rtsp_url: str | None,
                onvif_url: str | None, username: str | None) -> None:
    db.execute("""INSERT INTO cameras(ip, approved_at, rtsp_url, onvif_url, username)
                  VALUES (?, ?, ?, ?, ?)
                  ON CONFLICT(ip) DO UPDATE SET approved_at=excluded.approved_at,
                  rtsp_url=excluded.rtsp_url, onvif_url=excluded.onvif_url,
                  username=excluded.username""",
               (ip, utc_now(), rtsp_url, onvif_url, username))
    db.commit()


def get_camera(db: sqlite3.Connection, ip: str) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM cameras WHERE ip = ?", (ip,)).fetchone()


def export_report(report: dict, destination: Path) -> Path:
    private_dir(destination.parent)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)
        file.write("\n")
    return destination

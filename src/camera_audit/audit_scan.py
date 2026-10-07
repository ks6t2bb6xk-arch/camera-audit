"""Shared scan workflow for the command line and local interface."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from . import onvif, scanner, storage
from .nvd import NVDClient, enrich_hosts


SCAN_PROFILE = "nmap -sn; -sT -sV --version-light --top-ports 1000 -T3 -Pn"


def run_scan(db, cidr: str, *, offline: bool = False, destination: Path | None = None,
             progress: Callable[[str], None] | None = None,
             scan_fn=None, enrich_fn=None, cancel_event=None) -> tuple[int, dict, Path]:
    """Run an already approved scope and persist its evidence report."""
    scope = storage.get_scope(db, cidr)
    target = scope["cidr"]
    scan_fn = scan_fn or scanner.scan
    enrich_fn = enrich_fn or enrich_hosts
    if progress:
        progress("Discovering live hosts")
        scan_options = {"progress": progress}
        if cancel_event is not None:
            scan_options["cancel_event"] = cancel_event
        hosts = scan_fn(target, onvif.discover_devices, **scan_options)
        progress("Checking versioned CPEs against NVD")
    else:
        hosts = scan_fn(target, onvif.discover_devices)
    if cancel_event is not None and cancel_event.is_set():
        raise scanner.ScanCancelled("Scan cancelled.")
    if cancel_event is not None:
        enrich_fn(hosts, NVDClient(db, offline=offline), cancel_event=cancel_event)
    else:
        enrich_fn(hosts, NVDClient(db, offline=offline))
    if cancel_event is not None and cancel_event.is_set():
        raise scanner.ScanCancelled("Scan cancelled.")
    report = {
        "schema_version": 1,
        "created_at": storage.utc_now(),
        "cidr": target,
        "scan_profile": SCAN_PROFILE,
        "hosts": hosts,
        "note": "CVE matches indicate potential impact based on version/CPE data; they do not confirm a vulnerability or exploitation.",
    }
    if progress:
        progress("Saving the report")
    scan_id = storage.save_scan(db, report)
    path = destination or storage.data_dir() / "reports" / f"scan-{scan_id}.json"
    storage.export_report(report, path)
    return scan_id, report, path

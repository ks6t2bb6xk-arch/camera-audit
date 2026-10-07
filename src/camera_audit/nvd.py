"""Conservative CPE-based NVD lookup with a local SQLite cache."""

from __future__ import annotations

import json
import re
import sqlite3
import time
from datetime import datetime, timezone

import requests


API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_FIELD = re.compile(r"^[A-Za-z0-9._~+%-]{1,120}$")
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
CACHE_SECONDS = 24 * 3600


def normalized_cpe(raw: str) -> str | None:
    if raw.startswith("cpe:2.3:"):
        fields = raw.split(":")
        if len(fields) != 13:
            return None
        values = fields[2:]
    elif raw.startswith("cpe:/"):
        values = raw[5:].split(":")
        if len(values) < 4 or len(values) > 11:
            return None
        values += ["*"] * (11 - len(values))
    else:
        return None
    if values[0] not in ("a", "h", "o"):
        return None
    if any(not CPE_FIELD.fullmatch(item) for item in values[1:4]):
        return None
    if any(item in ("*", "-") for item in values[1:4]):
        return None
    if any(not (item in ("*", "-") or CPE_FIELD.fullmatch(item)) for item in values[4:]):
        return None
    return "cpe:2.3:" + ":".join(values)


def _score(cve: dict) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics", {})
    for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(name) or []
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity") or entries[0].get("baseSeverity")
    return None, None


def _summarize(payload: dict) -> list[dict]:
    findings = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        identifier = cve.get("id", "")
        if not CVE_ID.fullmatch(identifier) or cve.get("vulnStatus") == "Rejected":
            continue
        score, severity = _score(cve)
        descriptions = cve.get("descriptions", [])
        english = next((value.get("value") for value in descriptions if value.get("lang") == "en"), None)
        findings.append({
            "id": identifier,
            "status": "potential impact",
            "score": score,
            "severity": severity,
            "description": english[:500] if english else None,
            "url": f"https://nvd.nist.gov/vuln/detail/{identifier}",
        })
    return findings


class NVDClient:
    def __init__(self, db: sqlite3.Connection, offline: bool = False):
        self.db = db
        self.offline = offline
        self._last_request = 0.0

    def lookup(self, cpe: str) -> tuple[list[dict], str, str | None]:
        row = self.db.execute("SELECT fetched_at, payload_json FROM nvd_cache WHERE cpe = ?", (cpe,)).fetchone()
        if row:
            age = datetime.now(timezone.utc).timestamp() - datetime.fromisoformat(row["fetched_at"]).timestamp()
            if age < CACHE_SECONDS:
                return json.loads(row["payload_json"]), "cache", row["fetched_at"]
        if self.offline:
            return (json.loads(row["payload_json"]), "stale_cache", row["fetched_at"]) if row else ([], "offline_unavailable", None)
        try:
            elapsed = time.monotonic() - self._last_request
            if self._last_request and elapsed < 6:
                time.sleep(6 - elapsed)
            self._last_request = time.monotonic()
            response = requests.get(API_URL + "?isVulnerable",
                                    params={"cpeName": cpe, "resultsPerPage": 2000},
                                    headers={"User-Agent": "camera-audit/0.2"}, timeout=20)
            response.raise_for_status()
            payload = response.json()
            if payload.get("totalResults", 0) > payload.get("resultsPerPage", 2000):
                # Avoid presenting an incomplete CVE list as exhaustive.
                raise ValueError("NVD result count exceeds a single page")
            findings = _summarize(payload)
            fetched_at = datetime.now(timezone.utc).isoformat()
            self.db.execute("INSERT OR REPLACE INTO nvd_cache(cpe, fetched_at, payload_json) VALUES (?, ?, ?)",
                            (cpe, fetched_at, json.dumps(findings)))
            self.db.commit()
            return findings, "live", fetched_at
        except (requests.RequestException, ValueError, KeyError):
            return (json.loads(row["payload_json"]), "stale_cache", row["fetched_at"]) if row else ([], "lookup_unavailable", None)


def enrich_hosts(hosts: list[dict], client: NVDClient, cancel_event=None) -> None:
    from .scanner import ScanCancelled
    memo: dict[str, tuple[list[dict], str, str | None]] = {}
    for host in hosts:
        if cancel_event is not None and cancel_event.is_set():
            raise ScanCancelled("Scan cancelled.")
        host["vulnerabilities"] = []
        host["nvd_status"] = "no_versioned_cpe"
        for port in host["ports"]:
            for raw_cpe in port.get("cpes", []):
                if cancel_event is not None and cancel_event.is_set():
                    raise ScanCancelled("Scan cancelled.")
                cpe = normalized_cpe(raw_cpe)
                if not cpe:
                    continue
                if host["ip"] in cpe or (host.get("mac") and host["mac"].lower() in cpe.lower()):
                    # A malformed fingerprint must never put target identifiers in an external query.
                    continue
                if cpe not in memo:
                    memo[cpe] = client.lookup(cpe)
                findings, status, fetched_at = memo[cpe]
                host["nvd_status"] = status
                for finding in findings:
                    if any(existing["id"] == finding["id"] for existing in host["vulnerabilities"]):
                        continue
                    host["vulnerabilities"].append({**finding, "evidence": {
                        "port": port["port"], "service": port.get("service"),
                        "product": port.get("product"), "version": port.get("version"),
                        "cpe": cpe, "source": "NVD CVE API", "fetched_at": fetched_at,
                        "lookup_status": status,
                    }})

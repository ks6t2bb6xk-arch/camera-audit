"""Command line interface for authorized camera audits."""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import shutil
import sys
from pathlib import Path

from . import __version__
from . import onvif, preview, scanner, storage
from .nvd import NVDClient, enrich_hosts


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="camera-audit", description="İzinli ağlarda kamera envanteri ve güvenlik denetimi")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Yerel bağımlılıkları kontrol et")
    scope = commands.add_parser("scope", help="İzinli CIDR allowlist'ini yönet")
    scope_cmd = scope.add_subparsers(dest="scope_command", required=True)
    add = scope_cmd.add_parser("add")
    add.add_argument("cidr")
    add.add_argument("--non-private", action="store_true", help="Özel olmayan izinli lab CIDR'si")
    scope_cmd.add_parser("list")
    remove = scope_cmd.add_parser("remove")
    remove.add_argument("cidr")
    scan = commands.add_parser("scan", help="İzinli CIDR'yi Nmap ile tara")
    scan.add_argument("cidr")
    scan.add_argument("--offline", action="store_true", help="Yalnızca yerel NVD önbelleğini kullan")
    scan.add_argument("--json", type=Path, help="Rapor dosyası; varsayılan uygulama veri dizininde")
    report = commands.add_parser("report", help="Kaydedilmiş taramayı göster")
    report.add_argument("scan_id", nargs="?", type=int)
    report.add_argument("--json", type=Path, help="Raporu JSON olarak dışa aktar")
    cameras = commands.add_parser("cameras", help="Kamera adayları ve onayları")
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
    watch = commands.add_parser("preview", help="Onaylanan kameranın canlı akışını aç")
    watch.add_argument("ip")
    return parser


def _doctor() -> int:
    print(f"Nmap: {shutil.which('nmap') or 'yok'}")
    print(f"ffplay: {shutil.which('ffplay') or 'yok'}")
    try:
        import av
        print(f"PyAV: {av.__version__}")
    except ImportError:
        print("PyAV: yok (önizleme için camera-audit[preview] kurun)")
    try:
        print(f"Anahtarlık: {type(preview._keyring().get_keyring()).__module__}")
    except preview.PreviewError as exc:
        print(f"Anahtarlık: {exc}")
    print(f"Veri dizini: {storage.data_dir()}")
    return 0


def _scope(args, db) -> int:
    if args.scope_command == "add":
        cidr, non_private = storage.add_scope(db, args.cidr, args.non_private)
        print(f"Kapsama eklendi: {cidr}" + (" (özel olmayan lab aralığı)" if non_private else ""))
    elif args.scope_command == "list":
        for row in db.execute("SELECT cidr, non_private FROM scopes ORDER BY cidr"):
            print(row["cidr"] + ("  [özel olmayan]" if row["non_private"] else ""))
    else:
        cidr = str(ipaddress.ip_network(args.cidr, strict=True))
        db.execute("DELETE FROM scopes WHERE cidr = ?", (cidr,))
        db.commit()
        print(f"Kapsamdan çıkarıldı: {cidr}")
    return 0


def _confirm_scan(cidr: str, non_private: bool, input_fn=None) -> bool:
    input_fn = input if input_fn is None else input_fn
    print(f"Hedef: {cidr}")
    print("Profil: canlı cihaz keşfi; ilk 1000 TCP portu; hafif servis/sürüm tespiti (-T3).")
    print("Bu aralık için tarama yetkiniz olduğunu doğrulayın.")
    if non_private:
        return input_fn(f"Devam için CIDR'yi aynen yazın ({cidr}): ").strip() == cidr
    return input_fn("Taramayı başlatmak için 'evet' yazın: ").strip().lower() == "evet"


def _summary(report: dict) -> None:
    print(f"Tarama: {report['cidr']} | {report['created_at']} | {len(report['hosts'])} canlı cihaz")
    for host in report["hosts"]:
        label = " [KAMERA ADAYI]" if host["camera_candidate"] else ""
        ports = ", ".join(f"{port['port']}/{port['protocol']} {port.get('service') or '?'}" for port in host["ports"])
        print(f"{host['ip']}{label} | {ports or 'açık TCP portu bulunmadı'}")
        if host["camera_candidate"]:
            print("  Kanıt: " + "; ".join(host["camera_evidence"]))
        for finding in host.get("vulnerabilities", []):
            print(f"  {finding['id']} — olası etkilenme; CVSS {finding.get('score') or '?'}; {finding['url']}")
        if host.get("nvd_status") in ("lookup_unavailable", "offline_unavailable", "stale_cache"):
            print(f"  NVD durumu: {host['nvd_status']}")


def _scan(args, db) -> int:
    scope = storage.get_scope(db, args.cidr)
    cidr = scope["cidr"]
    if not _confirm_scan(cidr, bool(scope["non_private"])):
        print("Tarama iptal edildi.")
        return 1
    print("Nmap keşfi ve servis taraması çalışıyor…", flush=True)
    hosts = scanner.scan(cidr, onvif.discover)
    print(f"{len(hosts)} canlı cihaz bulundu; NVD eşleştirmesi yapılıyor…", flush=True)
    enrich_hosts(hosts, NVDClient(db, offline=args.offline))
    report = {"schema_version": 1, "created_at": storage.utc_now(), "cidr": cidr,
              "scan_profile": "nmap -sn; -sT -sV --version-light --top-ports 1000 -T3 -Pn",
              "hosts": hosts,
              "note": "CVE eşleşmeleri sürüm/CPE bilgisine dayalı olası etkilenmedir; doğrulanmış sömürü değildir."}
    scan_id = storage.save_scan(db, report)
    destination = args.json or storage.data_dir() / "reports" / f"scan-{scan_id}.json"
    storage.export_report(report, destination)
    _summary(report)
    print(f"JSON raporu: {destination}")
    return 0


def _report(args, db) -> int:
    report = storage.scan_by_id(db, args.scan_id) if args.scan_id else None
    if report is None and args.scan_id is None:
        latest = storage.latest_scan(db)
        report = latest[1] if latest else None
    if report is None:
        raise ValueError("Tarama raporu bulunamadı.")
    _summary(report)
    if args.json:
        print(f"JSON raporu: {storage.export_report(report, args.json)}")
    return 0


def _last_host(db, ip: str) -> dict:
    ip = str(ipaddress.ip_address(ip))
    latest = storage.latest_scan(db)
    if latest is None:
        raise ValueError("Önce tarama yapın.")
    host = next((item for item in latest[1]["hosts"] if item["ip"] == ip), None)
    if host is None:
        raise ValueError("Cihaz son taramada bulunamadı.")
    return host


def _cameras(args, db) -> int:
    if args.camera_command == "candidates":
        latest = storage.latest_scan(db)
        if latest is None:
            raise ValueError("Önce tarama yapın.")
        for host in latest[1]["hosts"]:
            if host["camera_candidate"]:
                print(f"{host['ip']}: {', '.join(host['camera_evidence'])}")
        return 0
    if args.camera_command == "list":
        for row in db.execute("SELECT ip, rtsp_url, onvif_url, username FROM cameras ORDER BY ip"):
            print(f"{row['ip']} | RTSP: {row['rtsp_url'] or '-'} | ONVIF: {row['onvif_url'] or '-'} | kullanıcı: {row['username'] or '-'}")
        return 0
    ip = str(ipaddress.ip_address(args.ip))
    if args.camera_command == "credentials":
        camera = storage.get_camera(db, ip)
        if camera is None:
            raise ValueError("Kamera onaylanmamış.")
        password = getpass.getpass("Kamera parolası (sistem anahtarlığında saklanır): ")
        preview.save_password(ip, password)
        storage.save_camera(db, ip, camera["rtsp_url"], camera["onvif_url"], args.username)
        print("Kimlik bilgileri kaydedildi.")
        return 0
    host = _last_host(db, ip)
    if not host["camera_candidate"]:
        raise ValueError("Bu cihaz son taramada kamera adayı olarak işaretlenmedi.")
    rtsp_url = args.rtsp_url
    onvif_url = args.onvif_url or host.get("onvif_url")
    if rtsp_url:
        onvif.validate_device_url(rtsp_url, ip, ("rtsp", "rtsps"))
    if onvif_url:
        onvif.validate_device_url(onvif_url, ip, ("http", "https"))
    if not rtsp_url and not onvif_url:
        raise ValueError("--rtsp-url sağlayın veya ONVIF adresi keşfedilmiş olmalı.")
    if args.username:
        password = getpass.getpass("Kamera parolası (sistem anahtarlığında saklanır): ")
        preview.save_password(ip, password)
    storage.save_camera(db, ip, rtsp_url, onvif_url, args.username)
    print(f"Kamera onaylandı: {ip}")
    return 0


def _preview(args, db) -> int:
    ip = str(ipaddress.ip_address(args.ip))
    camera = storage.get_camera(db, ip)
    if camera is None:
        raise ValueError("Kamera onaylanmamış.")
    password = preview.load_password(ip) if camera["username"] else None
    if camera["username"] and password is None:
        raise preview.PreviewError("Parola anahtarlıkta yok; 'cameras credentials' kullanın.")
    uri = camera["rtsp_url"] or onvif.get_stream_uri(camera["onvif_url"], ip, camera["username"], password)
    print("Canlı önizleme açılıyor. Kapatmak için Ctrl+C.")
    preview.play(uri, ip, camera["username"], password)
    return 0


def main(argv: list[str] | None = None) -> int:
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
    except (ValueError, EOFError, OSError, scanner.ScanError, onvif.OnvifError, preview.PreviewError) as exc:
        print(f"Hata: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

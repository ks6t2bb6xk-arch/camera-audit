"""Bounded Nmap inventory and camera candidate detection."""

from __future__ import annotations

import ipaddress
import re
import subprocess
import xml.etree.ElementTree as ET


CAMERA_WORDS = re.compile(r"(?:camera|cam|onvif|hikvision|dahua|axis|reolink|amcrest|uniview|vivotek)", re.I)
CAMERA_VENDORS = re.compile(r"(?:hikvision|dahua|axis|reolink|amcrest|uniview|vivotek|hanwha)", re.I)


class ScanError(RuntimeError):
    pass


def _run_nmap(args: list[str], timeout: int) -> str:
    try:
        result = subprocess.run(["nmap", *args], capture_output=True, text=True,
                                timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise ScanError("Nmap kurulu değil.") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError("Nmap zaman aşımına uğradı.") from exc
    if result.returncode != 0:
        # Nmap stderr may contain target names or other network data; do not echo it.
        raise ScanError(f"Nmap başarısız oldu (çıkış kodu {result.returncode}).")
    return result.stdout


def parse_nmap(xml_text: str) -> list[dict]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ScanError("Nmap XML çıktısı okunamadı.") from exc
    hosts: list[dict] = []
    for node in root.findall("host"):
        status = node.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip, mac, vendor = None, None, None
        for address in node.findall("address"):
            if address.get("addrtype") == "ipv4":
                ip = address.get("addr")
            elif address.get("addrtype") == "mac":
                mac = address.get("addr")
                vendor = address.get("vendor")
        if not ip:
            continue
        name_node = node.find("hostnames/hostname")
        hostname = name_node.get("name") if name_node is not None else None
        ports = []
        for port in node.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            ports.append({
                "protocol": port.get("protocol"),
                "port": int(port.get("portid", "0")),
                "service": service.get("name") if service is not None else None,
                "product": service.get("product") if service is not None else None,
                "version": service.get("version") if service is not None else None,
                "extrainfo": service.get("extrainfo") if service is not None else None,
                "cpes": [cpe.text for cpe in service.findall("cpe") if cpe.text] if service is not None else [],
            })
        hosts.append({"ip": ip, "hostname": hostname, "mac": mac,
                      "mac_vendor": vendor, "ports": ports})
    return hosts


def candidate_evidence(host: dict, onvif_url: str | None = None) -> list[str]:
    evidence = []
    if onvif_url:
        evidence.append("ONVIF WS-Discovery yanıtı")
    for port in host["ports"]:
        service = (port.get("service") or "").lower()
        product = " ".join(str(port.get(field) or "") for field in ("product", "extrainfo"))
        if service == "rtsp" or port["port"] in (554, 8554):
            evidence.append(f"RTSP işareti: TCP {port['port']}")
        elif CAMERA_WORDS.search(product):
            evidence.append(f"Servis ürünü kamera işareti: TCP {port['port']}")
    if CAMERA_WORDS.search(host.get("hostname") or ""):
        evidence.append("Hostname kamera işareti")
    if CAMERA_VENDORS.search(host.get("mac_vendor") or ""):
        evidence.append("MAC üreticisi kamera işareti")
    return list(dict.fromkeys(evidence))


def scan(cidr: str, onvif_discovery=None) -> list[dict]:
    network = ipaddress.ip_network(cidr, strict=True)
    if network.version != 4:
        raise ScanError("Bu sürüm yalnızca IPv4 CIDR taramasını destekler.")
    discovery = parse_nmap(_run_nmap(["-sn", "-oX", "-", str(network)], 300))
    live_ips = [host["ip"] for host in discovery if ipaddress.ip_address(host["ip"]) in network]
    if not live_ips:
        return []
    # All addresses are obtained from Nmap XML and checked against the approved CIDR.
    service_xml = _run_nmap(["-sT", "-sV", "--version-light", "--top-ports", "1000",
                             "-T3", "-Pn", "-oX", "-", *live_ips], 1200)
    service_hosts = {host["ip"]: host for host in parse_nmap(service_xml)
                     if ipaddress.ip_address(host["ip"]) in network}
    found_onvif = onvif_discovery(network) if onvif_discovery else {}
    output = []
    for discovered in discovery:
        ip = discovered["ip"]
        if ip not in live_ips:
            continue
        host = service_hosts.get(ip, discovered)
        host["mac"] = host.get("mac") or discovered.get("mac")
        host["mac_vendor"] = host.get("mac_vendor") or discovered.get("mac_vendor")
        host["hostname"] = host.get("hostname") or discovered.get("hostname")
        host["onvif_url"] = found_onvif.get(ip)
        host["camera_evidence"] = candidate_evidence(host, host["onvif_url"])
        host["camera_candidate"] = bool(host["camera_evidence"])
        output.append(host)
    return sorted(output, key=lambda host: ipaddress.ip_address(host["ip"]))

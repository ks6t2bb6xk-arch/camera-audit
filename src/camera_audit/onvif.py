"""Small, read-only ONVIF discovery and stream URI client."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import socket
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import urlsplit
from xml.sax.saxutils import escape

import requests
from requests.auth import HTTPDigestAuth


class OnvifError(RuntimeError):
    pass


def validate_device_url(url: str, ip: str, schemes: tuple[str, ...]) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in schemes or parsed.hostname != ip or parsed.username or parsed.password:
        raise ValueError("URL protokolü veya hedef IP onaylanan kamerayla eşleşmiyor; URL'de parola olamaz.")
    if parsed.fragment:
        raise ValueError("URL fragment içeremez.")
    return url


def _find_text(root: ET.Element, local_name: str) -> str | None:
    for item in root.iter():
        if item.tag.rsplit("}", 1)[-1] == local_name and item.text:
            return item.text.strip()
    return None


def discover(network: ipaddress.IPv4Network, timeout: float = 2.0) -> dict[str, str]:
    message_id = uuid.uuid4()
    probe = (f'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
             f'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
             f'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
             f'<s:Header><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>'
             f'<a:MessageID>uuid:{message_id}</a:MessageID>'
             f'<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To></s:Header>'
             f'<s:Body><d:Probe/></s:Body></s:Envelope>')
    found: dict[str, str] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(probe.encode(), ("239.255.255.250", 3702))
            while True:
                try:
                    payload, source = sock.recvfrom(65535)
                except socket.timeout:
                    break
                ip = source[0]
                if ipaddress.ip_address(ip) not in network:
                    continue
                try:
                    root = ET.fromstring(payload)
                    addresses = (_find_text(root, "XAddrs") or "").split()
                    for address in addresses:
                        if urlsplit(address).hostname == ip:
                            found[ip] = validate_device_url(address, ip, ("http", "https"))
                            break
                except (ET.ParseError, ValueError):
                    continue
    except OSError:
        # Nmap inventory still works on networks that block multicast.
        return {}
    return found


def _security_header(username: str | None, password: str | None) -> str:
    if not username or password is None:
        return ""
    nonce = os.urandom(16)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    digest = base64.b64encode(hashlib.sha1(nonce + created.encode() + password.encode()).digest()).decode()
    encoded_nonce = base64.b64encode(nonce).decode()
    return ("<s:Header><wsse:Security s:mustUnderstand=\"1\" "
            "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" "
            "xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
            "<wsse:UsernameToken>"
            f"<wsse:Username>{escape(username)}</wsse:Username>"
            f"<wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">{digest}</wsse:Password>"
            f"<wsse:Nonce>{encoded_nonce}</wsse:Nonce><wsu:Created>{created}</wsu:Created>"
            "</wsse:UsernameToken></wsse:Security></s:Header>")


def _request(url: str, ip: str, body: str, username: str | None, password: str | None) -> ET.Element:
    validate_device_url(url, ip, ("http", "https"))
    envelope = ("<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
                "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
                "xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" "
                "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
                + _security_header(username, password) + "<s:Body>" + body + "</s:Body></s:Envelope>")
    try:
        response = requests.post(url, data=envelope.encode(),
                                 headers={"Content-Type": "application/soap+xml; charset=utf-8"},
                                 auth=HTTPDigestAuth(username, password) if username and password else None,
                                 timeout=8, allow_redirects=False)
        response.raise_for_status()
        if len(response.content) > 1_000_000:
            raise OnvifError("ONVIF yanıtı beklenenden büyük.")
        root = ET.fromstring(response.content)
    except (requests.RequestException, ET.ParseError) as exc:
        raise OnvifError("ONVIF isteği başarısız; erişim veya kimlik bilgilerini kontrol edin.") from exc
    if _find_text(root, "Fault") or any(el.tag.rsplit("}", 1)[-1] == "Fault" for el in root.iter()):
        raise OnvifError("Kamera ONVIF isteğini reddetti.")
    return root


def get_stream_uri(device_url: str, ip: str,
                   username: str | None, password: str | None) -> str:
    capabilities = _request(device_url, ip, "<tds:GetCapabilities><tds:Category>Media</tds:Category></tds:GetCapabilities>",
                            username, password)
    media_url = None
    for el in capabilities.iter():
        if el.tag.rsplit("}", 1)[-1] == "Media":
            media_url = _find_text(el, "XAddr")
            if media_url:
                break
    if not media_url:
        raise OnvifError("Kamera ONVIF Media adresi bildirmedi.")
    validate_device_url(media_url, ip, ("http", "https"))
    profiles = _request(media_url, ip, "<trt:GetProfiles/>", username, password)
    token = None
    for el in profiles.iter():
        if el.tag.rsplit("}", 1)[-1] == "Profiles":
            token = el.attrib.get("token")
            if token:
                break
    if not token:
        raise OnvifError("Kamera ONVIF medya profili bildirmedi.")
    body = ("<trt:GetStreamUri><trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream>"
            "<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>"
            f"</trt:StreamSetup><trt:ProfileToken>{escape(token)}</trt:ProfileToken></trt:GetStreamUri>")
    response = _request(media_url, ip, body, username, password)
    uri = _find_text(response, "Uri")
    if not uri:
        raise OnvifError("Kamera RTSP URI bildirmedi.")
    return validate_device_url(uri, ip, ("rtsp", "rtsps"))

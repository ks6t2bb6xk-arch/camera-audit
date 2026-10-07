"""Bounded, read-only RTSP endpoint discovery for one authorized host."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import socket
import time
from dataclasses import dataclass


DEFAULT_PATHS = ("", "live", "live/ch0", "stream1", "Streaming/Channels/101", "h264Preview_01_main")
MAX_PATHS = 8
MAX_ENDPOINTS = 12
MAX_RESPONSE = 65_536
MAX_HEADER = 16_384
TIMEOUT = 2.5


@dataclass(frozen=True)
class ProbeResult:
    url: str
    status: str  # valid, auth_required, not_found, timeout, unavailable
    detail: str = ""


@dataclass(frozen=True)
class _Response:
    code: int
    headers: dict[str, str]
    body: bytes


class _ProbeTimeout(Exception):
    pass


class _ProbeFailure(Exception):
    pass


def _paths(paths: tuple[str, ...] | list[str]) -> list[str]:
    if len(paths) > MAX_PATHS:
        raise ValueError(f"At most {MAX_PATHS} RTSP paths may be tested.")
    result = []
    for value in paths:
        path = value.lstrip("/")
        if len(path) > 80 or ".." in path or not re.fullmatch(r"[A-Za-z0-9_./-]*", path):
            raise ValueError("RTSP paths must be short path segments without credentials or query strings.")
        if path not in result:
            result.append(path)
    return result


def _read_response(sock: socket.socket, deadline: float, expect_body: bool) -> _Response:
    received = bytearray()
    while b"\r\n\r\n" not in received:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _ProbeTimeout
        sock.settimeout(remaining)
        chunk = sock.recv(4096)
        if not chunk:
            raise _ProbeFailure
        received.extend(chunk)
        if len(received) > MAX_HEADER and b"\r\n\r\n" not in received:
            raise _ProbeFailure
    head, body = bytes(received).split(b"\r\n\r\n", 1)
    if len(head) > MAX_HEADER:
        raise _ProbeFailure
    lines = head.decode("iso-8859-1").split("\r\n")
    status = re.fullmatch(r"RTSP/\d\.\d\s+(\d{3})(?:\s+.*)?", lines[0])
    if not status:
        raise _ProbeFailure
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    try:
        length = int(headers["content-length"]) if "content-length" in headers else None
    except ValueError as exc:
        raise _ProbeFailure from exc
    if length is not None and (length < 0 or length > MAX_RESPONSE):
        raise _ProbeFailure
    if length is None and not expect_body:
        return _Response(int(status.group(1)), headers, b"")
    while len(body) < (length if length is not None else MAX_RESPONSE):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if length is not None and len(body) < length:
                raise _ProbeTimeout
            break
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            if length is not None and len(body) < length:
                raise _ProbeTimeout from None
            break
        if not chunk:
            break
        body += chunk
        if len(body) > MAX_RESPONSE:
            raise _ProbeFailure
    if length is not None and len(body) < length:
        raise _ProbeFailure
    return _Response(int(status.group(1)), headers, body[:length] if length is not None else body)


def _exchange(ip: str, port: int, url: str, method: str,
              authorization: str | None = None) -> _Response:
    request = (f"{method} {url} RTSP/1.0\r\nCSeq: 1\r\n"
               "User-Agent: camera-audit/0.2\r\nAccept: application/sdp\r\nConnection: close\r\n")
    if authorization:
        request += f"Authorization: {authorization}\r\n"
    request += "\r\n"
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            deadline = time.monotonic() + TIMEOUT
            sock.settimeout(TIMEOUT)
            sock.sendall(request.encode("ascii"))
            return _read_response(sock, deadline, method == "DESCRIBE")
    except socket.timeout as exc:
        raise _ProbeTimeout from exc
    except OSError as exc:
        raise _ProbeFailure from exc


def _authorization(challenge: str, method: str, url: str,
                   username: str, password: str, allow_basic: bool) -> str | None:
    if challenge.lower().startswith("basic"):
        if not allow_basic:
            return None
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        return f"Basic {encoded}"
    if not challenge.lower().startswith("digest"):
        return None
    parameters = {match.group(1).lower(): match.group(2) or match.group(3)
                  for match in re.finditer(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', challenge)}
    realm, nonce = parameters.get("realm"), parameters.get("nonce")
    if not realm or not nonce or parameters.get("algorithm", "MD5").upper() != "MD5":
        return None
    if any(ord(char) < 32 or ord(char) > 126 for char in username + realm + nonce):
        return None
    qop = parameters.get("qop")
    if qop and "auth" not in [item.strip() for item in qop.split(",")]:
        return None
    md5 = lambda value: hashlib.md5(value.encode()).hexdigest()
    ha1 = md5(f"{username}:{realm}:{password}")
    ha2 = md5(f"{method}:{url}")
    quote_value = lambda value: value.replace("\\", "\\\\").replace('"', '\\"')
    fields = [f'username="{quote_value(username)}"', f'realm="{quote_value(realm)}"', f'nonce="{quote_value(nonce)}"',
              f'uri="{url}"', "algorithm=MD5"]
    if qop:
        cnonce = secrets.token_hex(8)
        response = md5(f"{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}")
        fields.extend(["qop=auth", "nc=00000001", f'cnonce="{cnonce}"'])
    else:
        response = md5(f"{ha1}:{nonce}:{ha2}")
    fields.append(f'response="{response}"')
    return "Digest " + ", ".join(fields)


def _valid_sdp(response: _Response) -> bool:
    if response.code != 200 or response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/sdp":
        return False
    lines = [line.strip() for line in response.body.replace(b"\r\n", b"\n").split(b"\n")]
    return (b"v=0" in lines and any(line.startswith(b"o=") for line in lines)
            and any(line.startswith(b"s=") for line in lines)
            and any(line.startswith(b"t=") for line in lines)
            and any(line.startswith(b"m=video ") for line in lines))


def probe(ip: str, port: int, path: str, username: str | None = None,
          password: str | None = None, allow_basic: bool = False) -> ProbeResult:
    """Send OPTIONS and DESCRIBE; credentials are tried once for this endpoint."""
    import ipaddress

    address = str(ipaddress.IPv4Address(ip))
    if not 1 <= port <= 65535:
        raise ValueError("Invalid RTSP port.")
    clean_path = _paths([path])[0]
    url = f"rtsp://{address}:{port}/{clean_path}"
    try:
        options = _exchange(address, port, url, "OPTIONS")
        if options.code not in (200, 401, 405, 501):
            return ProbeResult(url, "not_found" if options.code == 404 else "unavailable",
                               f"RTSP OPTIONS returned {options.code}")
        response = _exchange(address, port, url, "DESCRIBE")
        if response.code == 401 and username and password is not None:
            auth = _authorization(response.headers.get("www-authenticate", ""), "DESCRIBE",
                                  url, username, password, allow_basic)
            if auth:
                response = _exchange(address, port, url, "DESCRIBE", auth)
        if _valid_sdp(response):
            return ProbeResult(url, "valid", "Valid video SDP")
        if response.code == 401:
            scheme = response.headers.get("www-authenticate", "").split(" ", 1)[0].lower()
            detail = "RTSP Basic authentication required" if scheme == "basic" else "RTSP authentication required"
            return ProbeResult(url, "auth_required", detail)
        if response.code == 404:
            return ProbeResult(url, "not_found", "RTSP path not found")
        return ProbeResult(url, "unavailable", f"RTSP DESCRIBE returned {response.code}; no valid video SDP")
    except _ProbeTimeout:
        return ProbeResult(url, "timeout", "RTSP request timed out")
    except _ProbeFailure:
        return ProbeResult(url, "unavailable", "RTSP endpoint did not return a usable response")


def discover(ip: str, ports: list[int], paths: tuple[str, ...] | list[str] = DEFAULT_PATHS) -> list[ProbeResult]:
    """Probe a small path list, sequentially, on ports observed in the last scan."""
    candidates = _paths(paths)
    endpoints = [(port, path) for port in dict.fromkeys(ports) for path in candidates]
    if len(endpoints) > MAX_ENDPOINTS:
        endpoints = endpoints[:MAX_ENDPOINTS]
    return [probe(ip, port, path) for port, path in endpoints]

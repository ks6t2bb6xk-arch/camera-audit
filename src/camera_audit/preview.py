"""Credential handling and live, non-recording ffplay preview."""

from __future__ import annotations

import shutil
import subprocess
import sys
from urllib.parse import quote, urlsplit, urlunsplit

from .onvif import validate_device_url


SERVICE_NAME = "camera-audit"


class PreviewError(RuntimeError):
    pass


def _keyring():
    try:
        import keyring
        backend = keyring.get_keyring()
    except Exception as exc:
        raise PreviewError("Sistem anahtarlığı kullanılamıyor.") from exc
    module = type(backend).__module__.lower()
    if sys.platform == "darwin" and "macos" not in module:
        raise PreviewError("macOS Keychain arka ucu bulunamadı.")
    if sys.platform.startswith("linux") and "secretservice" not in module:
        raise PreviewError("Linux Secret Service arka ucu bulunamadı.")
    if not (sys.platform == "darwin" or sys.platform.startswith("linux")):
        raise PreviewError("Bu platformda güvenli kimlik bilgisi deposu desteklenmiyor.")
    return keyring


def save_password(ip: str, password: str) -> None:
    try:
        _keyring().set_password(SERVICE_NAME, ip, password)
    except Exception as exc:
        raise PreviewError("Parola sistem anahtarlığına kaydedilemedi.") from exc


def load_password(ip: str) -> str | None:
    try:
        return _keyring().get_password(SERVICE_NAME, ip)
    except Exception as exc:
        raise PreviewError("Parola sistem anahtarlığından okunamadı.") from exc


def _authenticated_uri(uri: str, ip: str, username: str | None, password: str | None) -> str:
    validate_device_url(uri, ip, ("rtsp", "rtsps"))
    if not username or password is None:
        return uri
    parts = urlsplit(uri)
    host = parts.netloc
    auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    return urlunsplit((parts.scheme, auth + host, parts.path, parts.query, ""))


def play(uri: str, ip: str, username: str | None, password: str | None) -> None:
    if not shutil.which("ffplay"):
        raise PreviewError("ffplay kurulu değil.")
    try:
        import av
    except ImportError as exc:
        raise PreviewError("Önizleme için 'pip install camera-audit[preview]' gerekli.") from exc
    authenticated = _authenticated_uri(uri, ip, username, password)
    player = None
    try:
        # The authenticated URL is only passed to PyAV in this process; ffplay sees raw frames.
        av.logging.set_level(av.logging.PANIC)
        with av.open(authenticated, options={"rtsp_transport": "tcp"}, timeout=8) as source:
            stream = next((item for item in source.streams if item.type == "video"), None)
            if stream is None:
                raise PreviewError("Akışta video kanalı bulunamadı.")
            for frame in source.decode(stream):
                rgb = frame.reformat(format="rgb24")
                width, height = rgb.width, rgb.height
                if player is None:
                    fps = float(stream.average_rate) if stream.average_rate else 25.0
                    fps = max(1.0, min(fps, 120.0))
                    player = subprocess.Popen(
                        ["ffplay", "-nostats", "-loglevel", "error", "-autoexit",
                         "-f", "rawvideo", "-pixel_format", "rgb24", "-video_size",
                         f"{width}x{height}", "-framerate", str(fps), "-i", "pipe:0"],
                        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    expected_size = (width, height)
                if (width, height) != expected_size:
                    raise PreviewError("Akış çözünürlüğü değişti; önizlemeyi yeniden açın.")
                if player.poll() is not None:
                    return
                plane = rgb.planes[0]
                raw = bytes(plane)
                stride = plane.line_size
                row_length = width * 3
                for row in range(height):
                    player.stdin.write(raw[row * stride:row * stride + row_length])
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        # The user may have closed the ffplay window directly.
        return
    except PreviewError:
        raise
    except Exception as exc:
        # PyAV exceptions may contain the full URL, including credentials.
        raise PreviewError("Canlı akış açılamadı; RTSP adresini ve kimlik bilgilerini kontrol edin.") from None
    finally:
        if player is not None:
            if player.stdin:
                try:
                    player.stdin.close()
                except OSError:
                    pass
            if player.poll() is None:
                player.terminate()
                try:
                    player.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    player.kill()
                    player.wait()

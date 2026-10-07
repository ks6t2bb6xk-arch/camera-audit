"""Credential handling and live, non-recording ffplay preview."""

from __future__ import annotations

import shutil
import subprocess
import sys
from urllib.parse import quote, urlsplit, urlunsplit

from .onvif import validate_device_url


SERVICE_NAME = "camera-audit"
STREAM_URL_SERVICE_NAME = "camera-audit-stream-url"


class PreviewError(RuntimeError):
    pass


def _keyring():
    try:
        import keyring
        backend = keyring.get_keyring()
    except Exception as exc:
        raise PreviewError("System credential manager is unavailable.") from exc
    module = type(backend).__module__.lower()
    if sys.platform == "darwin" and "macos" not in module:
        raise PreviewError("macOS Keychain backend was not found.")
    if sys.platform.startswith("linux") and "secretservice" not in module:
        raise PreviewError("Linux Secret Service backend was not found.")
    if not (sys.platform == "darwin" or sys.platform.startswith("linux")):
        raise PreviewError("Secure credential storage is not supported on this platform.")
    return keyring


def save_password(device_key: str, password: str) -> None:
    try:
        _keyring().set_password(SERVICE_NAME, device_key, password)
    except Exception as exc:
        raise PreviewError("Could not save the password to the system credential manager.") from exc


def load_password(device_key: str) -> str | None:
    try:
        return _keyring().get_password(SERVICE_NAME, device_key)
    except Exception as exc:
        raise PreviewError("Could not read the password from the system credential manager.") from exc


def save_stream_url(device_key: str, url: str) -> None:
    try:
        _keyring().set_password(STREAM_URL_SERVICE_NAME, device_key, url)
    except Exception as exc:
        raise PreviewError("Could not save the stream URL to the system credential manager.") from exc


def load_stream_url(device_key: str) -> str | None:
    try:
        return _keyring().get_password(STREAM_URL_SERVICE_NAME, device_key)
    except Exception as exc:
        raise PreviewError("Could not read the stream URL from the system credential manager.") from exc


def _authenticated_uri(uri: str, ip: str, username: str | None, password: str | None) -> str:
    validate_device_url(uri, ip, ("rtsp", "rtsps"))
    if not username or password is None:
        return uri
    parts = urlsplit(uri)
    host = parts.netloc
    auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    return urlunsplit((parts.scheme, auth + host, parts.path, parts.query, ""))


def play(uri: str, ip: str, username: str | None, password: str | None) -> bool:
    if not shutil.which("ffplay"):
        raise PreviewError("ffplay is not installed.")
    try:
        import av
    except ImportError as exc:
        raise PreviewError("Install or repair the camera-audit package to enable previews.") from exc
    authenticated = _authenticated_uri(uri, ip, username, password)
    player = None
    opened = False
    try:
        # The authenticated URL is only passed to PyAV in this process; ffplay sees raw frames.
        av.logging.set_level(av.logging.PANIC)
        with av.open(authenticated, options={"rtsp_transport": "tcp"}, timeout=8) as source:
            stream = next((item for item in source.streams if item.type == "video"), None)
            if stream is None:
                raise PreviewError("No video stream was found.")
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
                    raise PreviewError("Stream resolution changed; restart the preview.")
                if player.poll() is not None:
                    return opened
                plane = rgb.planes[0]
                raw = bytes(plane)
                stride = plane.line_size
                row_length = width * 3
                for row in range(height):
                    player.stdin.write(raw[row * stride:row * stride + row_length])
                opened = True
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        # The user may have closed the ffplay window directly.
        return opened
    except PreviewError:
        raise
    except Exception as exc:
        # PyAV exceptions may contain the full URL, including credentials.
        raise PreviewError("Could not open the live stream; check the RTSP URL and credentials.") from None
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
    return opened

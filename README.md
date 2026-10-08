# camera-audit

A Python tool for authorized IoT and IP camera security testing, with a simple local browser interface and optional command-line controls. It inventories live devices, fingerprints exposed services, checks versioned CPEs against NVD, and helps inspect camera stream endpoints. CVE matches and discovered endpoints are evidence for testing, not proof of a vulnerability or unauthenticated video access. The tool does not guess passwords, exploit devices, change camera settings, or record video. Reports contain findings and evidence, not remediation recommendations.

## Requirements

- Python 3.11 or newer
- Nmap for network scans
- FFmpeg's `ffplay` for live preview
- macOS Keychain or Linux Secret Service for saved credentials

Install Nmap and FFmpeg with `brew install nmap ffmpeg` on macOS or your distribution's package manager on Linux. Linux credential storage requires an active Secret Service session. There is no plaintext password fallback.

## Installation

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
camera-audit doctor
```

The existing `.[preview]` extra remains accepted for older installation instructions; preview support is included in the base package in V0.2.

## Browser interface

```sh
camera-audit
```

The command opens a private interface in your browser. Choose **Scan only** to inventory the authorized network and review live hosts, open services, camera candidates, and possible CVE matches. Choose **Scan + Watch** to run a fresh scan and select a camera for stream inspection. Both modes prefill the default-route network, and you can edit the CIDR before approving the exact target. A non-private lab CIDR requires typing the entire CIDR as confirmation.

Results are shown 50 devices per page. Use **Camera candidates only** to narrow the list; the summary counts and downloadable JSON report still cover the full scan.

Scan progress, camera selection, credentials, ONVIF profiles, manual RTSP URLs, and approvals are handled in the browser. **Cancel scan** stops an active scan without saving an unfinished report. Stream access and live preview require separate approvals. Video opens in a separate `ffplay` window. The interface binds only to `127.0.0.1`; its session token stays in the page and is not written to browser storage. Use **Close app** when finished.

The CLI remains available for advanced workflows. For example, `camera-audit scan --local` scans the detected network, and `camera-audit watch` uses the latest saved scan. If no scan exists, CLI `watch` offers a local scan:

```sh
camera-audit watch
```

The CLI lists camera candidates with services, RTSP ports, vendor, and connection status. Select a camera by number. The tool asks before probing its stream endpoints and again before opening live video.

For a previously scanned candidate, you can select it directly or inspect it without opening video:

```sh
camera-audit watch 192.168.1.20
camera-audit cameras inspect 192.168.1.20
```

ONVIF discovery checks the camera's media profiles and lets you choose when more than one is available. If ONVIF cannot provide a stream URI, bounded RTSP discovery checks only the selected camera's RTSP ports from the latest scan. It sends sequential `OPTIONS` and `DESCRIBE` requests to a short path list. A path is reported as verified only after a valid video SDP response. You can replace the default path list with up to eight explicit paths by repeating `--rtsp-path PATH`. If discovery fails, `watch` offers manual RTSP URL entry for that camera.

Authentication prompts use hidden password input. Passwords are saved in the system credential manager under a device identity derived from an ONVIF UUID or MAC address when available. A changed device identity requires new approval; a changed IP also requires approval before reusing saved connection details. If no stable identity is available, approval is tied to the scan. Use `camera-audit cameras credentials IP --username NAME` to update saved credentials. RTSP Basic authentication over plaintext requires a separate confirmation.

### Scan a specific network

The local shortcut detects the private IPv4 network on your default-route interface and adds it to the allowlist after confirmation:

```sh
camera-audit scan --local
```

For another authorized CIDR, use the explicit scope workflow:

```sh
camera-audit scope add 192.168.1.0/24
camera-audit scope list
camera-audit scan 192.168.1.0/24
```

Every scan displays its exact CIDR and requires confirmation. For an authorized lab range outside private address space, use `camera-audit scope add CIDR --non-private`; scan confirmation then requires typing the CIDR exactly. A scope can contain at most 4,096 IPv4 addresses. Automatic local detection is supported on macOS and Linux and stops when a VPN is the default route or the local subnet is ambiguous or too large.

### Existing camera commands

The explicit approval and preview commands remain available:

```sh
camera-audit cameras candidates
camera-audit cameras approve 192.168.1.20 --rtsp-url rtsp://192.168.1.20:554/stream1 --username admin
camera-audit preview 192.168.1.20
camera-audit report
```

Use your camera's actual RTSP path and never put a username or password in the URL. ONVIF discovery can supply an endpoint when `--rtsp-url` is omitted. Legacy IP-only approvals from V0.1 require one-time reapproval before credentials are reused.

## Reports and local data

Each scan prints a summary and saves JSON to `reports/scan-ID.json` in the application data directory. `scan --json PATH` and `report --json PATH` select another output path. The SQLite database and default reports are restricted to the current user.

- macOS: `~/Library/Application Support/camera-audit`
- Linux: `${XDG_DATA_HOME:-~/.local/share}/camera-audit`

Passwords are never written to SQLite or JSON. Stream URLs containing query parameters are stored in the credential manager. The tool does not use files or notifications from the earlier alarm application.

## Interpreting findings

NVD is queried only for versioned CPEs reported by Nmap. An empty CVE list for a service without a CPE does not mean that service is secure. IP addresses, MAC addresses, and stream details are not sent to NVD. CVE matches include the CPE, port, version, source, and lookup time. Confirm a finding separately before calling it a vulnerability. Offline and unavailable lookups are identified by their cache status.

An RTSP `401` response indicates authentication is required; it does not prove that a tested path exists. A valid SDP response identifies a stream endpoint but does not prove that unauthenticated live video is available. `watch` opens video only after explicit confirmation, decodes it in memory, and pipes raw frames to `ffplay` without creating a video file.

## Development

```sh
python -m unittest discover -s tests -v
```

The tests use sample Nmap XML, mocked ONVIF and RTSP responses, and a fake player. They do not require a camera, internet access, or a real network scan. Reinstall with `python -m pip install .` after changing the source code.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

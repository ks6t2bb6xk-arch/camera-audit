"""Discover the IPv4 network used by the system's default route."""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys
from dataclasses import dataclass


class LocalNetworkError(ValueError):
    pass


@dataclass(frozen=True)
class LocalNetwork:
    interface: str
    address: ipaddress.IPv4Address
    network: ipaddress.IPv4Network


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=5, check=False)
    except FileNotFoundError as exc:
        raise LocalNetworkError(f"Required system command was not found: {command[0]}.") from exc
    except subprocess.TimeoutExpired as exc:
        raise LocalNetworkError(f"System command timed out: {command[0]}.") from exc
    if result.returncode != 0:
        raise LocalNetworkError(f"Could not inspect the default network route ({command[0]} failed).")
    return result.stdout


def _default_interface() -> str:
    if sys.platform == "darwin":
        output = _run(["route", "-n", "get", "default"])
        match = re.search(r"^\s*interface:\s*(\S+)\s*$", output, re.MULTILINE)
    elif sys.platform.startswith("linux"):
        output = _run(["ip", "-4", "route", "show", "default"])
        first_route = next((line for line in output.splitlines() if line.strip()), "")
        match = re.search(r"(?:^|\s)dev\s+(\S+)", first_route)
    else:
        raise LocalNetworkError("Automatic local network detection supports macOS and Linux only.")
    if not match:
        raise LocalNetworkError("Could not identify the interface used by the default IPv4 route.")
    interface = match.group(1)
    if interface.lower().startswith(("utun", "tun", "tap", "wg", "ppp", "tailscale", "ipsec")):
        raise LocalNetworkError(
            f"The default route uses tunnel interface {interface}; disconnect the VPN or scan an explicit CIDR."
        )
    return interface


def _macos_addresses(interface: str) -> list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Network]]:
    output = _run(["ifconfig", interface])
    found = []
    for match in re.finditer(r"^\s+inet\s+(\d+(?:\.\d+){3})\s+netmask\s+(\S+)", output, re.MULTILINE):
        address = ipaddress.IPv4Address(match.group(1))
        mask = match.group(2)
        if mask.startswith("0x"):
            mask = str(ipaddress.IPv4Address(int(mask, 16)))
        network = ipaddress.IPv4Network(f"{address}/{mask}", strict=False)
        found.append((address, network))
    return found


def _linux_addresses(interface: str) -> list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Network]]:
    output = _run(["ip", "-j", "-4", "address", "show", "dev", interface])
    try:
        details = json.loads(output)
    except json.JSONDecodeError as exc:
        raise LocalNetworkError("Could not parse local IPv4 interface information.") from exc
    found = []
    for device in details:
        for address_info in device.get("addr_info", []):
            if address_info.get("family") != "inet" or address_info.get("scope") != "global":
                continue
            address = ipaddress.IPv4Address(address_info["local"])
            network = ipaddress.IPv4Network(f"{address}/{address_info['prefixlen']}", strict=False)
            found.append((address, network))
    return found


def detect() -> LocalNetwork:
    """Return the private IPv4 subnet on the default-route interface."""
    interface = _default_interface()
    addresses = _macos_addresses(interface) if sys.platform == "darwin" else _linux_addresses(interface)
    candidates = [(address, network) for address, network in addresses
                  if address.is_private and not address.is_loopback and not address.is_link_local]
    if len(candidates) != 1:
        raise LocalNetworkError(
            "Could not identify exactly one private IPv4 network on the default-route interface; "
            "specify an authorized CIDR explicitly."
        )
    address, network = candidates[0]
    return LocalNetwork(interface, address, network)

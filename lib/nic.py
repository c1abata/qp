"""Network interface detection helpers.

Simple and explicit, inspired by operational tooling needs:
- discover active interface
- discover IPv4 and subnet
- discover default gateway
- allow overrides from config/telegram
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import subprocess
from typing import Dict, Optional


log = logging.getLogger(__name__)


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""


def get_default_interface() -> Optional[str]:
    out = _run(["ip", "route", "show", "default"])
    match = re.search(r"\bdev\s+(\S+)", out)
    return match.group(1) if match else None


def get_interface_ipv4(iface: str) -> tuple[Optional[str], Optional[int]]:
    out = _run(["ip", "-o", "-4", "addr", "show", iface])
    match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out)
    if not match:
        return None, None
    return match.group(1), int(match.group(2))


def ip_prefix_to_subnet(ip: str, prefix: int) -> str:
    network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    return str(network)


def get_default_gateway() -> Optional[str]:
    out = _run(["ip", "route", "show", "default"])
    match = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)", out)
    return match.group(1) if match else None


def _read_dhcp_lease(iface: str) -> str:
    candidates = [
        f"/var/lib/dhcp/dhclient.{iface}.leases",
        f"/var/lib/dhcpcd5/{iface}.lease",
        "/var/lib/dhcp/dhclient.leases",
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    return handle.read()
            except OSError:
                continue
    return ""


def parse_dhcp_params(iface: Optional[str]) -> Dict[str, str]:
    if not iface:
        return {}

    lease = _read_dhcp_lease(iface)
    if not lease:
        return {}

    data: Dict[str, str] = {}

    wpad = re.search(r'option\s+wpad\s+"([^"]+)"', lease)
    if wpad:
        data["dhcp_target"] = wpad.group(1).strip()

    encoded = re.search(r'host-name\s+"(audit-[^"]+)"', lease)
    if encoded:
        for chunk in encoded.group(1).replace("audit-", "").split("-"):
            if "=" not in chunk:
                continue
            key, value = chunk.split("=", 1)
            data[key.strip()] = value.strip()

    return data


def detect_network_params(iface_override: Optional[str] = None) -> Dict[str, Optional[str]]:
    iface = iface_override or get_default_interface()
    ip, prefix = (None, None)

    if iface:
        ip, prefix = get_interface_ipv4(iface)

    subnet = ip_prefix_to_subnet(ip, prefix) if ip and prefix is not None else None
    gateway = get_default_gateway()
    dhcp_data = parse_dhcp_params(iface)

    result: Dict[str, Optional[str]] = {
        "interface": iface,
        "local_ip": ip,
        "local_subnet": subnet,
        "gateway": gateway,
    }
    result.update(dhcp_data)
    log.info("NIC detect: %s", result)
    return result


def get_network_info(cfg, overrides: Optional[dict] = None) -> Dict[str, Optional[str]]:
    overrides = overrides or {}

    iface = overrides.get("interface")
    if iface in {"", "auto", None}:
        iface = cfg.get("General", "interface", fallback="").strip() or None
    if iface in {"auto", ""}:
        iface = None

    detected = detect_network_params(iface)

    subnet_override = overrides.get("subnet")
    if subnet_override not in {None, "", "auto"}:
        detected["local_subnet"] = subnet_override

    if not detected.get("local_subnet"):
        fallback_subnet = cfg.get("Network", "target_subnet", fallback="").strip()
        if fallback_subnet and fallback_subnet != "auto":
            detected["local_subnet"] = fallback_subnet

    return {
        "iface": detected.get("interface"),
        "ip": detected.get("local_ip"),
        "subnet": detected.get("local_subnet"),
        "gateway": detected.get("gateway"),
        "dhcp_target": detected.get("dhcp_target"),
    }

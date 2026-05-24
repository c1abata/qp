"""Quick local posture snapshot for unfamiliar networks.

The task is intentionally local-first: it reads interface, route, resolver,
ARP neighbor and optional LLDP facts without sweeping the subnet.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess


def _run(cmd: list[str], timeout: int = 6) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (proc.stdout or "") + (proc.stderr or "")
    except Exception:
        return ""


def _private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _resolvers() -> list[str]:
    try:
        data = open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore").read()
    except OSError:
        return []
    return re.findall(r"^nameserver\s+(\S+)", data, flags=re.M)


def _arp_hosts() -> set[str]:
    out = _run(["ip", "neigh", "show"], timeout=5)
    hosts = set()
    for line in out.splitlines():
        match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+", line)
        if match:
            hosts.add(match.group(1))
    return hosts


def _wifi_ssid(iface: str | None) -> str:
    if not iface or not shutil.which("iwgetid"):
        return ""
    return _run(["iwgetid", iface, "--raw"], timeout=4).strip()


def run(context):
    net = context.get("net", {})
    iface = net.get("iface") or "unknown"
    ip = net.get("ip") or "unknown"
    subnet = net.get("subnet") or "unknown"
    gateway = net.get("gateway") or "unknown"
    resolvers = _resolvers()
    arp_hosts = _arp_hosts()
    ssid = _wifi_ssid(net.get("iface"))

    events = [{
        "type": "quickpeek_summary",
        "severity": "info",
        "message": (
            f"iface={iface} ip={ip} subnet={subnet} gateway={gateway} "
            f"resolvers={resolvers[:3]} arp_neighbors={len(arp_hosts)}"
            + (f" ssid={ssid}" if ssid else "")
        ),
        "source": "quickpeek",
    }]

    if ip != "unknown" and not _private(ip):
        events.append({
            "type": "quickpeek_public_ip",
            "severity": "warning",
            "message": f"Local interface has public IPv4 address: {ip}",
            "source": "quickpeek",
        })

    if gateway == "unknown":
        events.append({
            "type": "no_gateway",
            "severity": "warning",
            "message": "No default gateway detected",
            "source": "quickpeek",
        })

    public_resolvers = [item for item in resolvers if not _private(item)]
    if public_resolvers:
        events.append({
            "type": "quickpeek_public_dns",
            "severity": "info",
            "message": f"Public DNS resolvers configured: {public_resolvers[:3]}",
            "source": "quickpeek",
        })

    if len(arp_hosts) > 80:
        events.append({
            "type": "quickpeek_dense_lan",
            "severity": "info",
            "message": f"Large neighbor table observed: {len(arp_hosts)} IPv4 neighbors",
            "source": "quickpeek",
        })

    return events

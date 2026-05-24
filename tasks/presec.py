"""tasks/presec.py - pre-security baseline checks.

Fast checks only; deep scans are intentionally avoided by default.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess

from lib.ports import nmap_port_arg, parse_port_spec


AREA = "PRESEC"
DEFAULT_EGRESS_TCP_PORTS = "22,25,80,443,8189,10011,30033"
DEFAULT_LAN_TCP_PORTS = "22,23,445,3389,5900,8080,8443,8189,10011,30033"


def _run(cmd: list[str], timeout: int = 20) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (proc.stdout or "") + (proc.stderr or "")
    except Exception:
        return ""


def _write(path: str, content: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
    except OSError:
        pass


def check_path_to_internet(cfg, out_dir, alerter):
    findings = []

    target = cfg.get("General", "target_external", fallback="1.1.1.1").split(",")[0].strip()
    out = _run(["traceroute", "-n", "-m", "8", "-w", "1", "-q", "1", target], timeout=25)
    _write(os.path.join(out_dir, "traceroute.txt"), out)

    hops = re.findall(r"^\s*\d+\s+(\d+\.\d+\.\d+\.\d+|\*)", out, re.M)
    if not hops:
        msg = f"Traceroute failed to {target}"
        findings.append({"type": "traceroute", "severity": "warning", "message": msg, "source": "presec"})
        alerter.finding(AREA, msg, level="warning")
    else:
        msg = f"Traceroute collected {len(hops)} hops to {target}"
        findings.append({"type": "traceroute", "severity": "info", "message": msg, "source": "presec"})
        alerter.finding(AREA, msg, level="info")

    return findings


def check_egress_tcp(cfg, out_dir, alerter):
    findings = []

    target = cfg.get("General", "target_external", fallback="1.1.1.1").split(",")[0].strip()
    ports = parse_port_spec(cfg.get("Scan", "egress_tcp_ports", fallback=""), fallback=DEFAULT_EGRESS_TCP_PORTS)

    lines = []
    open_ports = []

    for port in ports:
        ok = False
        try:
            with socket.create_connection((target, port), timeout=2):
                ok = True
        except Exception:
            ok = False

        lines.append(f"{target}:{port} -> {'open' if ok else 'filtered'}")
        if ok:
            open_ports.append(port)

    _write(os.path.join(out_dir, "egress_tcp.txt"), "\n".join(lines))

    msg = f"TCP egress open ports to {target}: {open_ports}"
    findings.append({"type": "egress_tcp", "severity": "info", "message": msg, "source": "presec"})
    # SMTP open can be a risk only in some contexts; keep warning conservative.
    if 25 in open_ports:
        alerter.finding(AREA, f"SMTP egress open to {target}:25", level="warning")
    else:
        alerter.finding(AREA, msg, level="info")

    return findings


def check_lan_management_surface(cfg, out_dir, alerter):
    findings = []

    subnet = cfg.get("General", "local_subnet", fallback="")
    if not subnet:
        return findings

    if not shutil.which("nmap"):
        return findings

    ports = nmap_port_arg(cfg.get("Scan", "tcp_service_ports", fallback=""), fallback=DEFAULT_LAN_TCP_PORTS)
    if not ports:
        return findings

    out = _run(
        [
            "nmap",
            "-n",
            "-T2",
            "-p",
            ports,
            "--open",
            "--max-retries=1",
            "--host-timeout=20s",
            subnet,
        ],
        timeout=75,
    )
    _write(os.path.join(out_dir, "management_surface.txt"), out)

    telnet_hosts = sorted(set(re.findall(r"Nmap scan report for\s+(\S+)(?:.|\n)*?23/tcp\s+open", out)))
    rdp_hosts = sorted(set(re.findall(r"Nmap scan report for\s+(\S+)(?:.|\n)*?3389/tcp\s+open", out)))

    if telnet_hosts:
        msg = f"Telnet exposed on LAN hosts: {telnet_hosts[:10]}"
        findings.append({"type": "telnet_surface", "severity": "warning", "message": msg, "source": "presec"})
        alerter.finding(AREA, msg, level="warning")

    if rdp_hosts:
        msg = f"RDP exposed on LAN hosts: {rdp_hosts[:10]}"
        findings.append({"type": "rdp_surface", "severity": "info", "message": msg, "source": "presec"})
        alerter.finding(AREA, msg, level="info")

    return findings


def run(cfg, out_dir, alerter, mode="passive"):
    findings = []

    checks = [check_path_to_internet, check_egress_tcp]
    if mode == "active":
        checks.append(check_lan_management_surface)

    for check in checks:
        try:
            result = check(cfg, out_dir, alerter)
            if result:
                findings.extend(result)
        except Exception as exc:
            alerter.finding(AREA, f"{check.__name__} error: {exc}", level="error")

    return findings

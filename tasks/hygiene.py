"""tasks/hygiene.py - secure defaults with low false positives.

This module intentionally avoids aggressive checks unless explicitly enabled.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess


AREA = "HYGIENE"


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


def _policy_bool(cfg, key: str, default: bool = False) -> bool:
    raw = cfg.get("Policy", key, fallback=str(default)).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def check_arp_stability(cfg, out_dir, alerter):
    findings = []

    out = _run(["arp", "-an"], timeout=8)
    _write(os.path.join(out_dir, "arp_table.txt"), out)

    mac_to_ips = {}
    for line in out.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})", line.lower())
        if not m:
            continue
        ip, mac = m.group(1), m.group(2)
        mac_to_ips.setdefault(mac, set()).add(ip)

    noisy = {mac: sorted(ips) for mac, ips in mac_to_ips.items() if len(ips) >= 3}
    if noisy:
        msg = f"ARP instability detected (MAC mapped to >=3 IPs): {noisy}"
        findings.append({"type": "arp_stability", "severity": "warning", "message": msg, "source": "hygiene"})
        alerter.finding(AREA, msg, level="warning")

    return findings


def check_cleartext_exposure(cfg, out_dir, alerter):
    findings = []

    subnet = cfg.get("General", "local_subnet", fallback="")
    if not subnet:
        return findings

    if not shutil.which("nmap"):
        return findings

    out = _run(
        [
            "nmap",
            "-n",
            "-T2",
            "-p",
            "21,23,110,143,512,513,514",
            "--open",
            "--max-retries=1",
            "--host-timeout=20s",
            subnet,
        ],
        timeout=75,
    )
    _write(os.path.join(out_dir, "cleartext_surface.txt"), out)

    telnet_hosts = sorted(set(re.findall(r"Nmap scan report for\s+(\S+)(?:.|\n)*?23/tcp\s+open", out)))
    ftp_hosts = sorted(set(re.findall(r"Nmap scan report for\s+(\S+)(?:.|\n)*?21/tcp\s+open", out)))

    if telnet_hosts:
        msg = f"Telnet detected on hosts: {telnet_hosts[:10]}"
        findings.append({"type": "telnet_detected", "severity": "warning", "message": msg, "source": "hygiene"})
        alerter.finding(AREA, msg, level="warning")

    if ftp_hosts:
        msg = f"FTP detected on hosts: {ftp_hosts[:10]}"
        findings.append({"type": "ftp_detected", "severity": "info", "message": msg, "source": "hygiene"})
        alerter.finding(AREA, msg, level="info")

    return findings


def check_snmp_defaults(cfg, out_dir, alerter):
    findings = []

    if not _policy_bool(cfg, "enable_snmp_default_check", default=False):
        return findings

    subnet = cfg.get("General", "local_subnet", fallback="")
    if not subnet:
        return findings

    if not shutil.which("nmap") or not shutil.which("snmpget"):
        return findings

    out = _run(
        ["nmap", "-sU", "-n", "-T2", "-p", "161", "--open", "--max-retries=1", subnet],
        timeout=45,
    )
    _write(os.path.join(out_dir, "snmp_hosts.txt"), out)

    hosts = sorted(set(re.findall(r"Nmap scan report for\s+(\S+)", out)))
    accepted = []
    for host in hosts[:20]:
        probe = _run(["snmpget", "-v2c", "-c", "public", "-r1", "-t2", host, "1.3.6.1.2.1.1.1.0"], timeout=6)
        if "STRING:" in probe or "INTEGER:" in probe:
            accepted.append(host)

    _write(os.path.join(out_dir, "snmp_default_community.txt"), json.dumps({"accepted": accepted}, indent=2))

    if accepted:
        msg = f"SNMP default community 'public' accepted on hosts: {accepted}"
        findings.append({"type": "snmp_default", "severity": "warning", "message": msg, "source": "hygiene"})
        alerter.finding(AREA, msg, level="warning")

    return findings


def check_dns_policy_bypass(cfg, out_dir, alerter):
    findings = []

    # Fast network-level indicator: if DoH is reachable while policy forbids it, warn.
    forbid = _policy_bool(cfg, "doh_dot_forbidden", default=False)
    if not forbid:
        return findings

    out = _run(
        [
            "curl",
            "-sS",
            "-H",
            "accept: application/dns-json",
            "https://1.1.1.1/dns-query?name=example.com&type=A",
            "--max-time",
            "8",
            "-w",
            "\nHTTP:%{http_code}",
        ],
        timeout=10,
    )
    _write(os.path.join(out_dir, "doh_policy.txt"), out)

    if '"Status":0' in out.replace(" ", "") and "HTTP:200" in out:
        msg = "DoH reachable while policy forbids encrypted DNS egress"
        findings.append({"type": "doh_policy_bypass", "severity": "warning", "message": msg, "source": "hygiene"})
        alerter.finding(AREA, msg, level="warning")

    return findings


def run(cfg, out_dir, alerter, mode="passive"):
    findings = []
    seen = set()

    checks = [check_arp_stability, check_dns_policy_bypass]
    if mode == "active":
        checks.extend([check_cleartext_exposure, check_snmp_defaults])

    for check in checks:
        try:
            result = check(cfg, out_dir, alerter)
            if result:
                for item in result:
                    if isinstance(item, dict):
                        key = (item.get("type"), item.get("message"))
                    else:
                        key = ("generic", str(item))
                    if key not in seen:
                        seen.add(key)
                        findings.append(item)
        except Exception as exc:
            alerter.finding(AREA, f"{check.__name__} error: {exc}", level="error")

    return findings

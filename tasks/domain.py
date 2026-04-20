"""tasks/domain.py - lightweight domain/AD exposure checks."""

from __future__ import annotations

import os
import re
import shutil
import subprocess


AREA = "DOMAIN"


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


def _search_domain() -> str:
    try:
        resolv = open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore").read()
    except OSError:
        return ""

    for pattern in [r"^search\s+(\S+)", r"^domain\s+(\S+)"]:
        m = re.search(pattern, resolv, re.M)
        if m:
            value = m.group(1).strip().strip(".")
            if value and value != "local":
                return value
    return ""


def check_ad_records(cfg, out_dir, alerter):
    findings = []
    domain = _search_domain()
    if not domain:
        return findings

    records = [
        f"_ldap._tcp.{domain}",
        f"_kerberos._tcp.{domain}",
    ]

    lines = []
    found = []
    for rec in records:
        out = _run(["dig", rec, "SRV", "+short", "+time=2"])
        lines.append(f"== {rec} ==\n{out}\n")
        if out.strip():
            found.append(rec)

    _write(os.path.join(out_dir, "ad_srv_records.txt"), "\n".join(lines))

    if found:
        msg = f"AD-related SRV records found: {found}"
        findings.append({"type": "ad_srv", "severity": "info", "message": msg, "source": "domain"})
        # Informational: presence is not a vulnerability by itself.
        alerter.finding(AREA, msg, level="info")

    return findings


def check_ldap_smb_surface(cfg, out_dir, alerter):
    findings = []

    subnet = cfg["General"].get("local_subnet", "")
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
            "389,636,445",
            "--open",
            "--max-retries=1",
            "--host-timeout=20s",
            subnet,
        ],
        timeout=70,
    )
    _write(os.path.join(out_dir, "ldap_smb_surface.txt"), out)

    ldap_hosts = sorted(set(re.findall(r"Nmap scan report for\s+(\S+)(?:.|\n)*?389/tcp\s+open", out)))
    smb_hosts = sorted(set(re.findall(r"Nmap scan report for\s+(\S+)(?:.|\n)*?445/tcp\s+open", out)))

    if ldap_hosts:
        msg = f"LDAP services exposed on LAN hosts: {ldap_hosts[:10]}"
        findings.append({"type": "ldap_surface", "severity": "info", "message": msg, "source": "domain"})
        alerter.finding(AREA, msg, level="info")

    if smb_hosts:
        msg = f"SMB services exposed on LAN hosts: {smb_hosts[:10]}"
        findings.append({"type": "smb_surface", "severity": "info", "message": msg, "source": "domain"})
        alerter.finding(AREA, msg, level="info")

    return findings


def run(cfg, out_dir, alerter, mode="passive"):
    findings = []

    checks = [check_ad_records]
    if mode == "active":
        checks.append(check_ldap_smb_surface)

    for check in checks:
        try:
            result = check(cfg, out_dir, alerter)
            if result:
                findings.extend(result)
        except Exception as exc:
            alerter.finding(AREA, f"{check.__name__} error: {exc}", level="error")

    return findings

"""tasks/udp.py - fast UDP reachability checks."""

from __future__ import annotations

import os
import re
import shutil
import subprocess


AREA = "UDP"


def _run(cmd: list[str], timeout: int = 15) -> str:
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


def check_udp_dns(cfg, out_dir, alerter):
    findings = []

    target = cfg.get("General", "target_external", fallback="1.1.1.1").split(",")[0].strip()
    out = _run(["dig", f"@{target}", "example.com", "A", "+short", "+time=2", "+tries=1"], timeout=8)
    _write(os.path.join(out_dir, "udp_dns.txt"), out)

    if re.search(r"\d+\.\d+\.\d+\.\d+", out):
        msg = f"UDP DNS query succeeded to {target}:53"
        findings.append({"type": "udp_dns", "severity": "info", "message": msg, "source": "udp"})
        alerter.finding(AREA, msg, level="info")
    else:
        msg = f"UDP DNS query failed to {target}:53"
        findings.append({"type": "udp_dns", "severity": "warning", "message": msg, "source": "udp"})
        alerter.finding(AREA, msg, level="warning")

    return findings


def check_quic(cfg, out_dir, alerter):
    findings = []

    if not shutil.which("curl"):
        return findings

    out = _run(
        [
            "curl",
            "-sS",
            "--http3",
            "https://cloudflare.com",
            "-o",
            "/dev/null",
            "-w",
            "%{http_version}",
            "--max-time",
            "8",
        ],
        timeout=12,
    )
    _write(os.path.join(out_dir, "quic.txt"), out)

    if "3" in out:
        msg = "QUIC/HTTP3 reachable"
        findings.append({"type": "quic", "severity": "info", "message": msg, "source": "udp"})
        alerter.finding(AREA, msg, level="info")

    return findings


def check_udp_surface(cfg, out_dir, alerter):
    findings = []

    if not shutil.which("nmap"):
        return findings

    target = cfg.get("General", "target_external", fallback="1.1.1.1").split(",")[0].strip()
    out = _run(
        [
            "nmap",
            "-sU",
            "-n",
            "-T2",
            "-p",
            "53,67,123,161,500,4500,1194",
            "--max-retries=1",
            "--host-timeout=20s",
            target,
        ],
        timeout=45,
    )
    _write(os.path.join(out_dir, "udp_surface.txt"), out)

    open_ports = sorted(set(re.findall(r"(\d+)/udp\s+open\b", out)))
    if open_ports:
        msg = f"Open UDP ports on target {target}: {open_ports}"
        findings.append({"type": "udp_surface", "severity": "warning", "message": msg, "source": "udp"})
        # warning only in active mode because this is reconnaissance info.
        alerter.finding(AREA, msg, level="warning")

    return findings


def run(cfg, out_dir, alerter, mode="passive"):
    findings = []

    checks = [check_udp_dns, check_quic]
    if mode == "active":
        checks.append(check_udp_surface)

    for check in checks:
        try:
            result = check(cfg, out_dir, alerter)
            if result:
                findings.extend(result)
        except Exception as exc:
            alerter.finding(AREA, f"{check.__name__} error: {exc}", level="error")

    return findings

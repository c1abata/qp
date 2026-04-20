"""tasks/dns.py - fast DNS integrity checks with policy-aware severity."""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess


AREA = "DNS"


def _run(cmd: list[str], timeout: int = 12) -> str:
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


def check_resolution(cfg, out_dir, alerter):
    findings = []

    test_host = cfg.get("DNS", "test_hostname", fallback="example.com")

    resolved = []
    try:
        resolved = socket.getaddrinfo(test_host, 443, family=socket.AF_INET)
    except Exception:
        resolved = []

    if not resolved:
        msg = f"DNS A resolution failed for {test_host}"
        findings.append({"type": "dns_resolution", "severity": "warning", "message": msg, "source": "dns"})
        alerter.finding(AREA, msg, level="warning")
    else:
        addrs = sorted(set(item[4][0] for item in resolved if item and item[4]))
        msg = f"DNS resolution OK for {test_host}: {addrs[:3]}"
        findings.append({"type": "dns_resolution", "severity": "info", "message": msg, "source": "dns"})
        alerter.finding(AREA, msg, level="info")

    return findings


def check_plaintext_dns_path(cfg, out_dir, alerter):
    findings = []

    resolver = cfg.get("General", "target_external", fallback="1.1.1.1").split(",")[0].strip()
    out = _run(["dig", f"@{resolver}", "example.com", "A", "+short", "+time=2", "+tries=1"])
    _write(os.path.join(out_dir, "dns_plaintext.txt"), out)

    if re.search(r"\d+\.\d+\.\d+\.\d+", out):
        enforce = _policy_bool(cfg, "dns_plaintext_forbidden", default=False)
        level = "warning" if enforce else "info"
        msg = f"Plain DNS over port 53 reachable via resolver {resolver}"
        findings.append({"type": "dns_plaintext", "severity": level, "message": msg, "source": "dns"})
        alerter.finding(AREA, msg, level=level)

    return findings


def check_encrypted_dns(cfg, out_dir, alerter):
    findings = []

    if not shutil.which("openssl"):
        return findings

    dot_out = _run(
        [
            "openssl",
            "s_client",
            "-connect",
            "1.1.1.1:853",
            "-servername",
            "one.one.one.one",
            "-brief",
            "-verify_quiet",
        ],
        timeout=8,
    )
    _write(os.path.join(out_dir, "dot_probe.txt"), dot_out)

    dot_ok = "Verify return code: 0" in dot_out or "CONNECTION ESTABLISHED" in dot_out.upper()
    if dot_ok:
        forbid = _policy_bool(cfg, "doh_dot_forbidden", default=False)
        level = "warning" if forbid else "info"
        msg = "DoT endpoint reachable (1.1.1.1:853)"
        findings.append({"type": "dot_reachable", "severity": level, "message": msg, "source": "dns"})
        alerter.finding(AREA, msg, level=level)

    return findings


def run(cfg, out_dir, alerter, mode="passive"):
    findings = []

    checks = [
        check_resolution,
        check_plaintext_dns_path,
        check_encrypted_dns,
    ]

    for check in checks:
        try:
            result = check(cfg, out_dir, alerter)
            if result:
                findings.extend(result)
        except Exception as exc:
            alerter.finding(AREA, f"{check.__name__} error: {exc}", level="error")

    return findings

"""Passive STP/RSTP BPDU observation."""

from __future__ import annotations

import re
import shutil
import subprocess


BPDU_FILTER = "stp or ether dst 01:80:c2:00:00:00"


def _text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def run(net):
    iface = net.get("iface")
    if not iface:
        return [{"type": "rstp", "severity": "warning", "message": "No interface selected", "source": "rstp"}]

    if not shutil.which("tcpdump"):
        return [{"type": "rstp", "severity": "info", "message": "tcpdump not installed, RSTP check skipped", "source": "rstp"}]

    try:
        proc = subprocess.run(
            ["tcpdump", "-n", "-e", "-i", iface, "-c", "12", BPDU_FILTER],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired as exc:
        out = _text(exc.stdout) + _text(exc.stderr)
    except Exception as exc:
        return [{"type": "rstp", "severity": "warning", "message": f"RSTP check failed: {exc}", "source": "rstp"}]
    else:
        out = (proc.stdout or "") + (proc.stderr or "")

    text = out.strip()
    if not text:
        return [{"type": "rstp", "severity": "info", "message": "No STP/RSTP BPDUs observed", "source": "rstp"}]

    lowered = text.lower()
    if re.search(r"\brstp\b|802\.1w|rapid spanning", lowered):
        return [{"type": "rstp", "severity": "info", "message": "RSTP BPDUs observed on local segment", "source": "rstp"}]

    return [{"type": "stp", "severity": "info", "message": "STP BPDUs observed on local segment", "source": "rstp"}]

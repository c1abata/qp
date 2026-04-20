#!/usr/bin/env python3
"""Simple event correlation and deduplication.

Input event format:
{
  "type": "dns",
  "severity": "warning",
  "message": "...",
  "source": "task_name"
}
"""

from __future__ import annotations

from typing import Dict, List


SEVERITY_ORDER = {
    "info": 0,
    "warning": 1,
    "critical": 2,
    "error": 3,
}


def _normalized(event: dict) -> dict:
    e = dict(event)
    e["type"] = str(e.get("type", "generic")).strip() or "generic"
    sev = str(e.get("severity", "warning")).strip().lower()
    e["severity"] = sev if sev in SEVERITY_ORDER else "warning"
    e["message"] = str(e.get("message", "")).strip() or "(empty event)"
    e["source"] = str(e.get("source", "core")).strip() or "core"
    return e


def process(events: List[dict]) -> List[dict]:
    dedup: Dict[str, dict] = {}

    for raw in events:
        e = _normalized(raw)
        key = f"{e['type']}|{e['message']}"
        if key not in dedup:
            dedup[key] = e
            continue

        current = dedup[key]
        if SEVERITY_ORDER[e["severity"]] > SEVERITY_ORDER[current["severity"]]:
            dedup[key] = e

    out = list(dedup.values())

    types = {e["type"] for e in out}

    if "dhcp_rogue" in types and ("arp_spoof" in types or "mitm" in types):
        out.append({
            "type": "network_attack",
            "severity": "critical",
            "message": "Possible MITM via rogue DHCP infrastructure",
            "source": "correlator",
        })

    if "dns_tunnel" in types and ("doh_policy_bypass" in types or "doh_bypass" in types):
        out.append({
            "type": "dns_exfiltration_risk",
            "severity": "critical",
            "message": "Encrypted DNS bypass plus tunneling pattern detected",
            "source": "correlator",
        })

    return out

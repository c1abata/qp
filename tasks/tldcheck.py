"""Resolve unusual TLDs to detect filtering behavior."""

from __future__ import annotations

import socket


TLDS = [
    "example.zip",
    "example.mov",
    "example.crypto",
]


def run(net):
    events = []
    for domain in TLDS:
        try:
            socket.gethostbyname(domain)
            events.append({"type": "tld", "severity": "info", "message": f"TLD reachable: {domain}", "source": "tldcheck"})
        except Exception:
            events.append({"type": "tld", "severity": "warning", "message": f"TLD resolution blocked: {domain}", "source": "tldcheck"})
    return events

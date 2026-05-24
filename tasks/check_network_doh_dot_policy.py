"""Network DoH/DoT policy check with low-noise severity handling."""

from __future__ import annotations

import socket
import ssl
import urllib.request


AREA = "DOH_POLICY"


def _policy_bool(cfg, key: str, default: bool = False) -> bool:
    raw = cfg.get("Policy", key, fallback=str(default)).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _tcp_check(host: str, port: int, timeout: float = 3.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _dot_check(host: str, server_name: str) -> bool:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 853), timeout=4.5) as sock:
            with context.wrap_socket(sock, server_hostname=server_name):
                return True
    except Exception:
        return False


def _doh_check(url: str) -> bool:
    request = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(request, timeout=6) as resp:
            payload = resp.read(400).decode(errors="ignore")
            return resp.status == 200 and '"Status":0' in payload.replace(" ", "")
    except Exception:
        return False


def _probe_events() -> list[dict]:
    events = []

    dot_ok = _dot_check("1.1.1.1", "one.one.one.one")
    doh_ok = _doh_check("https://1.1.1.1/dns-query?name=example.com&type=A")
    dns53_ok = _tcp_check("1.1.1.1", 53)

    if dot_ok:
        events.append({"type": "doh_policy", "severity": "info", "message": "DoT on 853 reachable", "source": "check_network_doh_dot_policy"})
    if doh_ok:
        events.append({"type": "doh_policy", "severity": "info", "message": "DoH on 443 reachable", "source": "check_network_doh_dot_policy"})
    if dns53_ok:
        events.append({"type": "doh_policy", "severity": "info", "message": "DNS plaintext reachable on port 53", "source": "check_network_doh_dot_policy"})

    if not events:
        events.append({"type": "doh_policy", "severity": "info", "message": "No tested DoH/DoT path reachable", "source": "check_network_doh_dot_policy"})

    return events


def run(context):
    cfg = context.get("cfg")
    events = _probe_events()
    forbid = _policy_bool(cfg, "doh_dot_forbidden", default=False) if cfg else False
    if not forbid:
        return events
    for event in events:
        if "DoH" in event["message"] or "DoT" in event["message"]:
            event["severity"] = "warning"
            event["type"] = "doh_policy_bypass"
    return events

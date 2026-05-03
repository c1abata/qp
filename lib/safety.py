"""Safety guardrails for low-noise network checks."""

from __future__ import annotations

import ipaddress
from typing import Iterable


ACTIVE_SCAN_TASKS = {
    "domain",
    "hygiene",
    "net_discovery",
    "presec",
    "udp",
}

LOCAL_PASSIVE_TASKS = {
    "quickpeek",
    "net",
    "hygiene",
    "mitm_detect",
    "lldp_map",
    "passive_scan",
    "vlan_8021x",
}


def bool_value(raw: object, default: bool = False) -> bool:
    if raw is None:
        return default
    value = str(raw).strip().lower()
    if not value:
        return default
    return value in {"1", "true", "yes", "on"}


def subnet_host_count(subnet: str | None) -> int | None:
    if not subnet:
        return None
    try:
        return int(ipaddress.ip_network(str(subnet), strict=False).num_addresses)
    except ValueError:
        return None


def is_private_subnet(subnet: str | None) -> bool:
    if not subnet:
        return False
    try:
        network = ipaddress.ip_network(str(subnet), strict=False)
    except ValueError:
        return False
    return bool(network.is_private or network.is_link_local)


def select_tasks(profile: str, requested: Iterable[str], peek_tasks: Iterable[str]) -> list[str]:
    names = [str(item).strip().lower() for item in requested if str(item).strip()]
    if profile == "peek":
        allowed = set(peek_tasks)
        return [name for name in names if name in allowed] or list(peek_tasks)
    return names


def blocked_task_reason(task_name: str, mode: str, subnet: str | None, max_hosts: int, allow_large_scan: bool) -> str:
    if mode != "active" or task_name not in ACTIVE_SCAN_TASKS:
        return ""

    count = subnet_host_count(subnet)
    if count is None:
        return "active scan blocked: no valid local subnet detected"
    if not is_private_subnet(subnet):
        return f"active scan blocked: subnet is not private/link-local ({subnet})"
    if count > max_hosts and not allow_large_scan:
        return f"active scan blocked: subnet has {count} addresses, limit is {max_hosts}"
    return ""

#!/usr/bin/env python3
"""Task discovery and execution helpers.

Supports two task styles:
- legacy: run(cfg, out_dir, alerter, mode="passive|active")
- v4:     run(net)
"""

from __future__ import annotations

import importlib
import inspect
from typing import Any, Dict, Iterable, List, Tuple


DEFAULT_TASKS = [
    "net",
    "domain",
    "dns",
    "udp",
    "presec",
    "hygiene",
    "health",
    "net_discovery",
    "passive_scan",
    "dhcp_rogue",
    "vlan_8021x",
    "lldp_map",
    "mitm_detect",
    "tor",
    "tldcheck",
    "streaming",
    "dns_tunnelling",
    "check_network_doh_dot_policy",
]

PEEK_TASKS = [
    "quickpeek",
    "net",
    "hygiene",
    "mitm_detect",
    "lldp_map",
    "passive_scan",
    "vlan_8021x",
]


def parse_tasks(value: str | None) -> List[str]:
    if not value:
        return list(DEFAULT_TASKS)

    out: List[str] = []
    for item in value.split(","):
        name = item.strip().lower()
        if not name:
            continue
        out.append(name)
    return out or list(DEFAULT_TASKS)


def load_tasks(task_names: Iterable[str]) -> Tuple[List[tuple[str, Any]], List[str]]:
    loaded: List[tuple[str, Any]] = []
    errors: List[str] = []

    for name in task_names:
        module_name = f"tasks.{name}"
        try:
            module = importlib.import_module(module_name)
            if not hasattr(module, "run"):
                errors.append(f"Task load error {name}: run() not found")
                continue
            loaded.append((name, module))
        except Exception as exc:
            errors.append(f"Task load error {name}: {exc}")
    return loaded, errors


def _normalize_event(task_name: str, item: Any) -> dict:
    if isinstance(item, dict):
        event = dict(item)
    else:
        event = {
            "type": task_name,
            "severity": "info",
            "message": str(item),
        }
    event.setdefault("type", task_name)
    event.setdefault("severity", "warning")
    event.setdefault("message", "")
    event.setdefault("source", task_name)
    return event


def normalize_result(task_name: str, result: Any) -> List[dict]:
    if result is None:
        return []
    if isinstance(result, dict):
        return [_normalize_event(task_name, result)]
    if isinstance(result, (list, tuple)):
        return [_normalize_event(task_name, item) for item in result]
    return [_normalize_event(task_name, result)]


def execute_task(module: Any, task_name: str, ctx: Dict[str, Any]) -> Any:
    run_fn = getattr(module, "run")
    sig = inspect.signature(run_fn)
    params = list(sig.parameters.values())

    # legacy signature: run(cfg, out_dir, alerter, mode="...")
    if len(params) >= 3 and params[0].name in {"cfg", "config"}:
        return run_fn(ctx["cfg"], ctx["out_dir"], ctx["alerter"], mode=ctx["mode"])

    # v4 style: run(net)
    if len(params) == 1 and params[0].name in {"net", "network"}:
        return run_fn(ctx["net"])

    # generic context style: run(context)
    if len(params) == 1 and params[0].name in {"context", "ctx"}:
        return run_fn(ctx)

    # fallback for no-arg tasks
    if len(params) == 0:
        return run_fn()

    # last resort for flexible functions
    try:
        return run_fn(ctx["cfg"], ctx["out_dir"], ctx["alerter"], mode=ctx["mode"])
    except TypeError:
        return run_fn(ctx["net"])

#!/usr/bin/env python3
"""Runtime state utilities for QuickPeek.

Goals:
- keep state in a single JSON file
- avoid hard failures on constrained systems
- prefer /var/log/net_audit, fallback to local project runtime dir
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE = {
    "version": 1,
    "telegram_offset": 0,
    "overrides": {},
    "last_run": {},
    "last_events": [],
}


def _first_writable_path(candidates: list[Path]) -> Path:
    for path in candidates:
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".qp_write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return path
        except OSError:
            continue
    return candidates[-1]


def runtime_root() -> Path:
    return _first_writable_path([
        Path("/var/log/net_audit"),
        PROJECT_ROOT / "runtime",
    ])


def paths() -> Dict[str, str]:
    root = runtime_root()
    logs_dir = root / "logs"
    tasks_dir = root / "tasks"
    state_file = root / "state.json"
    logs_dir.mkdir(parents=True, exist_ok=True)
    tasks_dir.mkdir(parents=True, exist_ok=True)
    return {
        "root": str(root),
        "logs_dir": str(logs_dir),
        "tasks_dir": str(tasks_dir),
        "state_file": str(state_file),
    }


def load_state() -> Dict[str, Any]:
    p = Path(paths()["state_file"])
    if not p.exists():
        return dict(DEFAULT_STATE)

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return dict(DEFAULT_STATE)

    merged = dict(DEFAULT_STATE)
    if isinstance(data, dict):
        merged.update(data)
    if not isinstance(merged.get("overrides"), dict):
        merged["overrides"] = {}
    if not isinstance(merged.get("last_events"), list):
        merged["last_events"] = []
    if not isinstance(merged.get("last_run"), dict):
        merged["last_run"] = {}
    return merged


def save_state(state: Dict[str, Any]) -> None:
    safe = dict(DEFAULT_STATE)
    if isinstance(state, dict):
        safe.update(state)
    safe["updated_at"] = int(time.time())

    p = Path(paths()["state_file"])
    try:
        p.write_text(json.dumps(safe, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        # best-effort, never crash caller
        pass


def save_last_run(state: Dict[str, Any], network: Dict[str, Any], mode: str, summary: Dict[str, Any], events: list[dict]) -> Dict[str, Any]:
    now = int(time.time())
    state["last_run"] = {
        "timestamp": now,
        "mode": mode,
        "network": network,
        "summary": summary,
    }
    state["last_events"] = events[-200:]
    save_state(state)
    return state

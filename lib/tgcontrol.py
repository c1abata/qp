#!/usr/bin/env python3
"""Telegram control channel for QuickPeek.

Supported commands:
- /help
- /ping
- /status
- /mode passive|active
- /profile peek|audit
- /interface <iface>|auto
- /subnet <cidr>|auto
- /tasks
- /tasks set a,b,c
- /scan
"""

from __future__ import annotations

import requests
from typing import Dict, List


HELP = "\n".join([
    "QuickPeek bot commands:",
    "/help",
    "/ping",
    "/status",
    "/mode passive|active",
    "/profile peek|audit",
    "/interface <iface>|auto",
    "/subnet <cidr>|auto",
    "/tasks",
    "/tasks set net,dns,udp",
    "/policy",
    "/policy set dns_plaintext_forbidden true|false",
    "/policy set doh_dot_forbidden true|false",
    "/policy set enable_snmp_default_check true|false",
    "/scan",
])


def _enabled(cfg) -> bool:
    token = cfg.get("Telegram", "bot_token", fallback="").strip()
    chat = cfg.get("Telegram", "chat_id", fallback="").strip()
    return bool(token and chat)


def _token_chat(cfg):
    token = cfg.get("Telegram", "bot_token", fallback="").strip()
    chat = cfg.get("Telegram", "chat_id", fallback="").strip()
    return token, chat


def _send(token: str, chat_id: str, text: str) -> None:
    try:
        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=8,
        )
    except Exception:
        pass


def _status_from_state(state: dict) -> str:
    last = state.get("last_run", {}) if isinstance(state, dict) else {}
    summary = last.get("summary", {}) if isinstance(last, dict) else {}
    net = last.get("network", {}) if isinstance(last, dict) else {}
    mode = last.get("mode", "unknown")
    total = summary.get("total_events", 0)
    critical = summary.get("critical", 0)
    warning = summary.get("warning", 0)
    iface = net.get("iface", "?")
    subnet = net.get("subnet", "?")
    overrides = state.get("overrides", {}) if isinstance(state, dict) else {}
    policies = (
        f"dns_plaintext_forbidden={overrides.get('dns_plaintext_forbidden', 'config')} "
        f"doh_dot_forbidden={overrides.get('doh_dot_forbidden', 'config')} "
        f"enable_snmp_default_check={overrides.get('enable_snmp_default_check', 'config')}"
    )
    return (
        "QuickPeek status\n"
        f"mode: {mode}\n"
        f"iface: {iface}\n"
        f"subnet: {subnet}\n"
        f"events: total={total} warning={warning} critical={critical}\n"
        f"policy: {policies}"
    )


def _parse(text: str):
    parts = text.strip().split()
    if not parts:
        return "", []
    cmd = parts[0].lower()
    args = parts[1:]
    return cmd, args


def process(cfg, state: dict, available_tasks: List[str]) -> dict:
    """Read updates, apply overrides in state, and answer commands.

    Returns actions dictionary:
    {
      "force_scan": bool,
      "changed": bool,
      "messages": [debug lines]
    }
    """
    actions = {"force_scan": False, "changed": False, "messages": []}

    if not _enabled(cfg):
        return actions

    token, chat_id = _token_chat(cfg)
    offset = int(state.get("telegram_offset", 0) or 0)

    try:
        response = requests.get(
            f"https://api.telegram.org/bot{token}/getUpdates",
            params={"offset": offset, "timeout": 1},
            timeout=6,
        )
        payload = response.json() if response.ok else {}
    except Exception as exc:
        actions["messages"].append(f"telegram getUpdates error: {exc}")
        return actions

    if not payload.get("ok"):
        actions["messages"].append("telegram payload not ok")
        return actions

    overrides = state.setdefault("overrides", {})
    highest = offset

    for item in payload.get("result", []):
        update_id = int(item.get("update_id", 0))
        highest = max(highest, update_id + 1)

        msg = item.get("message") or item.get("edited_message") or {}
        src_chat = str((msg.get("chat") or {}).get("id", ""))
        text = (msg.get("text") or "").strip()

        if not text or src_chat != str(chat_id):
            continue

        cmd, args = _parse(text)

        if cmd == "/help":
            _send(token, chat_id, HELP)
            continue

        if cmd == "/ping":
            _send(token, chat_id, "pong")
            continue

        if cmd == "/status":
            _send(token, chat_id, _status_from_state(state))
            continue

        if cmd == "/scan":
            actions["force_scan"] = True
            _send(token, chat_id, "scan accepted")
            continue

        if cmd == "/mode":
            if args and args[0].lower() in {"passive", "active"}:
                overrides["mode"] = args[0].lower()
                actions["changed"] = True
                _send(token, chat_id, f"mode set to {overrides['mode']}")
            else:
                _send(token, chat_id, "usage: /mode passive|active")
            continue

        if cmd == "/profile":
            if args and args[0].lower() in {"peek", "audit"}:
                overrides["profile"] = args[0].lower()
                actions["changed"] = True
                _send(token, chat_id, f"profile set to {overrides['profile']}")
            else:
                _send(token, chat_id, "usage: /profile peek|audit")
            continue

        if cmd == "/interface":
            if args:
                overrides["interface"] = args[0]
                actions["changed"] = True
                _send(token, chat_id, f"interface set to {args[0]}")
            else:
                _send(token, chat_id, "usage: /interface eth0|auto")
            continue

        if cmd == "/subnet":
            if args:
                overrides["subnet"] = args[0]
                actions["changed"] = True
                _send(token, chat_id, f"subnet set to {args[0]}")
            else:
                _send(token, chat_id, "usage: /subnet 192.168.1.0/24|auto")
            continue

        if cmd == "/tasks":
            if args[:1] == ["set"] and len(args) >= 2:
                value = " ".join(args[1:]).replace(" ", "")
                requested = [x for x in value.split(",") if x]
                valid = [x for x in requested if x in available_tasks]
                if not valid:
                    _send(token, chat_id, "no valid tasks in request")
                else:
                    overrides["tasks"] = ",".join(valid)
                    actions["changed"] = True
                    _send(token, chat_id, f"tasks set: {', '.join(valid)}")
            else:
                current = overrides.get("tasks", "") or "default"
                _send(token, chat_id, f"available: {', '.join(available_tasks)}\ncurrent: {current}")
            continue

        if cmd == "/policy":
            if args[:1] == ["set"] and len(args) == 3:
                key = args[1].strip()
                value = args[2].strip().lower()
                allowed = {
                    "dns_plaintext_forbidden",
                    "doh_dot_forbidden",
                    "enable_snmp_default_check",
                }
                if key not in allowed or value not in {"true", "false"}:
                    _send(token, chat_id, "usage: /policy set <key> true|false")
                else:
                    overrides[key] = value
                    actions["changed"] = True
                    _send(token, chat_id, f"policy override set: {key}={value}")
            else:
                current = {
                    "dns_plaintext_forbidden": overrides.get("dns_plaintext_forbidden", "config"),
                    "doh_dot_forbidden": overrides.get("doh_dot_forbidden", "config"),
                    "enable_snmp_default_check": overrides.get("enable_snmp_default_check", "config"),
                }
                _send(
                    token,
                    chat_id,
                    "policy overrides\n"
                    f"dns_plaintext_forbidden={current['dns_plaintext_forbidden']}\n"
                    f"doh_dot_forbidden={current['doh_dot_forbidden']}\n"
                    f"enable_snmp_default_check={current['enable_snmp_default_check']}",
                )
            continue

        _send(token, chat_id, "unknown command, try /help")

    if highest != offset:
        state["telegram_offset"] = highest
        actions["changed"] = True

    return actions

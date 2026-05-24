#!/usr/bin/env python3
"""Alerting module: Telegram first, Bluetooth fallback, retry queue."""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Iterable, List

import requests

from lib.bluetooth_alert import BluetoothAlerter
from lib import runtime


log = logging.getLogger(__name__)

LEVEL_ICON = {
    "info": "[i]",
    "warning": "[!]",
    "critical": "[!!]",
    "error": "[x]",
    "ok": "[ok]",
}


class Alerter:
    def __init__(self, cfg):
        self.cfg = cfg
        self.token = cfg.get("Telegram", "bot_token", fallback="").strip()
        self.chat_id = cfg.get("Telegram", "chat_id", fallback="").strip()
        self.enabled = bool(self.token and self.chat_id)

        bt_mac = cfg.get("Bluetooth", "device_mac", fallback="").strip()
        self.bt = BluetoothAlerter(bt_mac) if bt_mac else None

        self._sent_cache = set()
        self._retry_file = os.path.join(runtime.paths()["root"], "pending_alerts.json")
        self._flush_pending()

    def finding(self, area: str, message: str, level: str = "warning") -> None:
        icon = LEVEL_ICON.get(level, "[*]")
        self.send(f"{icon} [{area}] {message}", level=level)

    def ok(self, area: str, message: str) -> None:
        self.send(f"{LEVEL_ICON['ok']} [{area}] {message}", level="ok")

    def send(self, message: str, level: str = "info") -> bool:
        if message in self._sent_cache:
            return False
        self._sent_cache.add(message)

        if self.enabled and self._telegram_send(message):
            return True

        if self.enabled:
            self._enqueue(message)
        if self.bt:
            self._bluetooth_send(message)
        return False

    def dispatch_events(self, events: Iterable[dict]) -> None:
        send_info = self.cfg.get("Alerts", "send_info", fallback="false").strip().lower() in {"1", "true", "yes", "on"}
        send_warning = self.cfg.get("Alerts", "send_warning", fallback="true").strip().lower() in {"1", "true", "yes", "on"}
        send_critical = self.cfg.get("Alerts", "send_critical", fallback="true").strip().lower() in {"1", "true", "yes", "on"}

        lines: List[str] = []
        bt_lines: List[str] = []
        for event in events:
            sev = str(event.get("severity", "warning")).lower()
            icon = LEVEL_ICON.get(sev, "[*]")
            msg = str(event.get("message", "")).strip()
            src = str(event.get("source", "core")).strip()
            if event.get("type") in {"no_gateway", "quickpeek_no_gateway"}:
                bt_lines.append(f"{icon} [{src}] {msg}")

            if sev == "info" and not send_info:
                continue
            if sev == "warning" and not send_warning:
                continue
            if sev in {"critical", "error"} and not send_critical:
                continue
            if sev not in {"info", "warning", "critical", "error"}:
                continue
            lines.append(f"{icon} [{src}] {msg}")

        telegram_delivered = False

        if lines:
            header = "QuickPeek alerts"
            payload = header + "\n" + "\n".join(lines[:30])
            telegram_delivered = self.send(payload, level="warning")

        if self.bt and bt_lines and (telegram_delivered or not lines):
            self._bluetooth_send("QuickPeek gateway alert\n" + "\n".join(bt_lines[:10]))

    def fetch_mode_override(self, default_mode: str = "passive") -> str:
        """Backward-compatible mode resolver.

        New architecture stores overrides in runtime state.
        """
        state = runtime.load_state()
        overrides = state.get("overrides", {}) if isinstance(state, dict) else {}
        mode = str(overrides.get("mode", default_mode)).lower().strip()
        return mode if mode in {"passive", "active"} else default_mode

    def _telegram_send(self, text: str, retries: int = 2) -> bool:
        if not self.enabled:
            return False

        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = {"chat_id": self.chat_id, "text": text}

        for attempt in range(retries):
            try:
                response = requests.post(url, json=payload, timeout=8)
                if response.status_code == 200:
                    return True
                log.warning("Telegram HTTP %s: %s", response.status_code, response.text[:120])
            except Exception as exc:
                log.warning("Telegram send attempt %s failed: %s", attempt + 1, exc)
                time.sleep(1)

        return False

    def _bluetooth_send(self, message: str) -> None:
        try:
            sent = self.bt.send(message)
            if not sent:
                log.warning("Bluetooth send returned false")
        except Exception as exc:
            log.warning("Bluetooth send error: %s", exc)

    def _enqueue(self, message: str) -> None:
        queue: List[dict] = []
        if os.path.exists(self._retry_file):
            try:
                with open(self._retry_file, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                if isinstance(data, list):
                    queue = data
            except Exception:
                queue = []

        queue.append({"ts": int(time.time()), "msg": message})

        try:
            with open(self._retry_file, "w", encoding="utf-8") as handle:
                json.dump(queue[-200:], handle)
        except Exception as exc:
            log.warning("Queue write failed: %s", exc)

    def _flush_pending(self) -> None:
        if not os.path.exists(self._retry_file):
            return

        try:
            with open(self._retry_file, "r", encoding="utf-8") as handle:
                queue = json.load(handle)
        except Exception:
            return

        if not isinstance(queue, list):
            return

        pending = []
        for item in queue:
            msg = str(item.get("msg", "")).strip()
            if not msg:
                continue
            if not self._telegram_send(f"[retry] {msg}"):
                pending.append(item)

        if pending:
            try:
                with open(self._retry_file, "w", encoding="utf-8") as handle:
                    json.dump(pending, handle)
            except Exception:
                pass
        else:
            try:
                os.remove(self._retry_file)
            except OSError:
                pass


# Backward-compatible decorator

def alertable(area: str, alerter: Alerter):
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                alerter.finding(area, f"{func.__name__} failed: {exc}", level="error")
                log.error("[%s] %s: %s", area, func.__name__, exc)
                return None

        wrapper.__name__ = func.__name__
        return wrapper

    return decorator

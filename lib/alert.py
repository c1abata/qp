#!/usr/bin/env python3
"""
lib/alert.py - Alerting modulare (Telegram + Bluetooth fallback)

Design:
- Alerter use from task
- Telegram frist
- Bluetooth fallback
- Queue persist
"""

import logging
import os
import json
import time
import re
import requests

from lib.bluetooth_alert import BluetoothAlerter

log = logging.getLogger(__name__)

LEVEL_ICON = {
    "info":     "ℹ️",
    "warning":  "⚠️",
    "critical": "🔴",
    "error":    "❌",
    "ok":       "✅",
}

RETRY_FILE = "/var/log/net_audit/pending_alerts.json"


class Alerter:

    def __init__(self, cfg):
        # Telegram
        self.token   = cfg.get("Telegram", "bot_token", fallback="")
        self.chat_id = cfg.get("Telegram", "chat_id", fallback="")
        self.enabled = bool(self.token and self.chat_id)

        # Bluetooth
        bt_mac = cfg.get("Bluetooth", "device_mac", fallback="")
        self.bt = BluetoothAlerter(bt_mac) if bt_mac else None

        # Anti-duplicate (runtime)
        self._sent_cache = set()

        # Retry queue flush
        self._flush_pending()

    def _state_root(self):
        preferred = "/var/log/net_audit"
        fallback = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "state")

        for root in (preferred, fallback):
            try:
                os.makedirs(root, exist_ok=True)
                test_file = os.path.join(root, ".write_test")
                with open(test_file, "w") as f:
                    f.write("")
                os.remove(test_file)
                return root
            except OSError:
                continue

        return fallback

    def _state_file(self):
        return os.path.join(self._state_root(), "telegram_state.json")

    def _load_state(self):
        path = self._state_file()
        if not os.path.exists(path):
            return {}
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_state(self, state):
        path = self._state_file()
        try:
            with open(path, "w") as f:
                json.dump(state, f)
        except Exception as e:
            log.warning(f"State save failed: {e}")

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------

    def finding(self, area: str, message: str, level: str = "warning"):
        icon = LEVEL_ICON.get(level, "•")
        text = f"{icon} *[{area}]* {message}"
        log.warning(f"FINDING [{area}] {message}")
        self.send(text, level)

    def send(self, message: str, level: str = "info"):
        """
        Notification order:
        1. Telegram
        2. Fail → enqueue + Bluetooth
        3. TG off -> Bluetooth diretto
        """

        # Anti-duplicate
        if message in self._sent_cache:
            return
        self._sent_cache.add(message)

        # --- TELEGRAM ---
        if self.enabled:
            success = self._telegram_send(message)

            if success:
                return

            # fallback
            log.warning("Telegram failed → fallback Bluetooth")
            self._enqueue(message)

            if self.bt:
                self._bluetooth_send(message)
            return

        # --- SOLO BLUETOOTH ---
        log.info("Telegram disabilitato → uso Bluetooth")
        if self.bt:
            self._bluetooth_send(message)

    def ok(self, area: str, message: str):
        log.info(f"OK [{area}] {message}")

    def fetch_mode_override(self, default_mode: str = "passive") -> str:
        """
        Resolve operational mode from Telegram commands and persist the last
        accepted value. Accepted commands:
        - /mode passive
        - /mode active
        - mode passive
        - mode active
        """
        state = self._load_state()
        current_mode = state.get("mode", default_mode).lower()

        if not self.enabled:
            return current_mode

        offset = state.get("telegram_update_offset", 0)
        url = f"https://api.telegram.org/bot{self.token}/getUpdates"

        try:
            response = requests.get(
                url,
                params={"timeout": 1, "offset": offset},
                timeout=5,
            )
            payload = response.json() if response.ok else {}
        except Exception as e:
            log.warning(f"Telegram getUpdates failed: {e}")
            return current_mode

        if not payload.get("ok"):
            return current_mode

        highest_update_id = offset - 1 if offset else 0
        for update in payload.get("result", []):
            update_id = update.get("update_id", 0)
            highest_update_id = max(highest_update_id, update_id)
            message = update.get("message") or update.get("edited_message") or {}
            chat_id = str(message.get("chat", {}).get("id", ""))
            text = (message.get("text") or "").strip()

            if chat_id != str(self.chat_id) or not text:
                continue

            match = re.search(r'^(?:/mode|mode)\s+(passive|active)\b', text, re.I)
            if match:
                current_mode = match.group(1).lower()

        if highest_update_id >= offset:
            state["telegram_update_offset"] = highest_update_id + 1
        state["mode"] = current_mode
        self._save_state(state)
        return current_mode

    # ------------------------------------------------------------------
    # TELEGRAM
    # ------------------------------------------------------------------

    def _telegram_send(self, text: str, retries: int = 2) -> bool:
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"

        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown"
        }

        for attempt in range(retries):
            try:
                r = requests.post(url, json=payload, timeout=8)

                if r.status_code == 200:
                    return True

                log.warning(f"Telegram HTTP {r.status_code}: {r.text[:120]}")

            except Exception as e:
                log.warning(f"Telegram tentativo {attempt+1}: {e}")
                time.sleep(2)

        return False

    # ------------------------------------------------------------------
    # BLUETOOTH
    # ------------------------------------------------------------------

    def _bluetooth_send(self, message: str):
        if not self.bt:
            return

        try:
            ok = self.bt.send(message)

            if ok:
                log.info("Send to Bluetooth")
            else:
                log.warning("Bluetooth failed send")

        except Exception as e:
            log.error(f"Bluetooth Error: {e}")

    # ------------------------------------------------------------------
    # RETRY QUEUE
    # ------------------------------------------------------------------

    def _enqueue(self, message: str):
        queue = []

        if os.path.exists(RETRY_FILE):
            try:
                queue = json.loads(open(RETRY_FILE).read())
            except Exception:
                pass

        queue.append({"ts": time.time(), "msg": message})

        try:
            os.makedirs(os.path.dirname(RETRY_FILE), exist_ok=True)

            with open(RETRY_FILE, "w") as f:
                json.dump(queue, f)

        except Exception as e:
            log.error(f"Enqueue failed: {e}")

    def _flush_pending(self):
        if not os.path.exists(RETRY_FILE):
            return

        try:
            queue = json.loads(open(RETRY_FILE).read())
        except Exception:
            return

        remaining = []

        for item in queue:
            if not self._telegram_send(f"[RETRY] {item['msg']}"):
                remaining.append(item)

        if remaining:
            with open(RETRY_FILE, "w") as f:
                json.dump(remaining, f)
        else:
            os.remove(RETRY_FILE)


# ---------------------------------------------------------------------------
# Decoratore
# ---------------------------------------------------------------------------

def alertable(area: str, alerter: Alerter):
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                alerter.finding(area, f"`{func.__name__}` failed: {exc}", level="error")
                log.error(f"[{area}] {func.__name__}: {exc}")
                return None
        wrapper.__name__ = func.__name__
        return wrapper
    return decorator

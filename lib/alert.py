#!/usr/bin/env python3
"""
lib/alert.py - Sistema di alerting modulare (Telegram + Bluetooth fallback)

Design:
- Tutti i task usano Alerter
- Telegram è canale principale
- Bluetooth è fallback immediato se Telegram fallisce
- Retry queue persistente
"""

import logging
import os
import json
import time
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
        Invio multi-canale:
        1. Telegram
        2. Se fallisce → enqueue + Bluetooth
        3. Se Telegram non configurato → Bluetooth diretto
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
            log.warning("Telegram fallito → fallback Bluetooth")
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
                log.info("Alert inviato via Bluetooth")
            else:
                log.warning("Bluetooth send fallito")

        except Exception as e:
            log.error(f"Errore Bluetooth: {e}")

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
            log.error(f"Enqueue fallito: {e}")

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
                alerter.finding(area, f"`{func.__name__}` fallito: {exc}", level="error")
                log.error(f"[{area}] {func.__name__}: {exc}")
                return None
        wrapper.__name__ = func.__name__
        return wrapper
    return decorator
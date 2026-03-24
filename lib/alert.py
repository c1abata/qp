"""
lib/alert.py - Sistema di alerting modulare.

Design:
  - Alerter è un oggetto passato a ogni task.
  - Ogni task chiama alerter.finding(area, msg) per i risultati rilevanti.
  - Livelli: info, warning, critical, error.
  - Se Telegram fallisce, accoda localmente e riprova.
  - Un decoratore @alertable rende qualunque funzione "notificabile" in 3 righe.
"""

import logging
import os
import json
import time
import requests

log = logging.getLogger(__name__)

# Emoji per livello
LEVEL_ICON = {
    "info":     "ℹ️",
    "warning":  "⚠️",
    "critical": "🔴",
    "error":    "❌",
    "ok":       "✅",
}

RETRY_FILE = "/var/log/net_audit/pending_alerts.json"


class Alerter:
    """
    Oggetto condiviso tra tutti i task.
    Uso:
        alerter.finding("NET", "Host sconosciuto trovato: 10.0.0.99", level="warning")
        alerter.send("Messaggio libero", level="info")
    """

    def __init__(self, cfg):
        self.token   = cfg.get("Telegram", "bot_token",  fallback="")
        self.chat_id = cfg.get("Telegram", "chat_id",    fallback="")
        self.enabled = bool(self.token and self.chat_id)
        self._flush_pending()   # riprova alert in coda dal run precedente

    # ------------------------------------------------------------------
    # API pubblica
    # ------------------------------------------------------------------

    def finding(self, area: str, message: str, level: str = "warning"):
        """Notifica un singolo finding da un'area specifica."""
        icon = LEVEL_ICON.get(level, "•")
        text = f"{icon} *[{area}]* {message}"
        log.warning(f"FINDING [{area}] {message}")
        self.send(text, level=level)

    def send(self, message: str, level: str = "info"):
        """Invia un messaggio Telegram. Su failure, accoda per retry."""
        if not self.enabled:
            log.info(f"[ALERT-disabled] {message}")
            return
        success = self._telegram_send(message)
        if not success:
            self._enqueue(message)

    def ok(self, area: str, message: str):
        """Shortcut per risultato pulito (opzionale, riduce il rumore)."""
        # Di default non inviamo gli "ok" per non spammare.
        log.info(f"OK [{area}] {message}")

    # ------------------------------------------------------------------
    # Interno
    # ------------------------------------------------------------------

    def _telegram_send(self, text: str, retries: int = 2) -> bool:
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = {
            "chat_id":    self.chat_id,
            "text":       text,
            "parse_mode": "Markdown",
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

    def _enqueue(self, message: str):
        """Salva il messaggio su file per retry al prossimo run."""
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
        """Al boot, riprova i messaggi accodati."""
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
        # Aggiorna il file
        if remaining:
            with open(RETRY_FILE, "w") as f:
                json.dump(remaining, f)
        else:
            os.remove(RETRY_FILE)


# ---------------------------------------------------------------------------
# Decoratore @alertable
#
# Rende qualunque funzione automaticamente notificante in caso di eccezione.
# Uso:
#   @alertable("NET", alerter)
#   def my_check():
#       ...  # se solleva, alerter.finding("NET", str(exc), "error")
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

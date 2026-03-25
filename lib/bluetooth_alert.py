#!/usr/bin/env python3
"""
lib/bluetooth_alert.py

Send alert Bluetooth (OBEX file push).
Fallback out-of-band.
"""

import subprocess
import tempfile
import logging

log = logging.getLogger(__name__)


class BluetoothAlerter:
    def __init__(self, mac: str):
        self.mac = mac

    def send(self, message: str) -> bool:
        """
        Send BT Msg with temp e OBEX.
        """
        if not self.mac:
            return False

        try:
            # 1. Scrive messaggio su file temporaneo
            with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
                f.write(message)
                path = f.name

            # 2. Tentativo connessione (best effort)
            subprocess.run(
                ["bluetoothctl", "connect", self.mac],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )

            # 3. Invio file via OBEX
            subprocess.run(
                [
                    "obexftp",
                    "--nopath",
                    "--noconn",
                    "--uuid", "none",
                    "--bluetooth", self.mac,
                    "--put", path
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10
            )

            log.info(f"BT send TO {self.mac}")
            return True

        except Exception as e:
            log.warning(f"BT send failed: {e}")
            return False
        
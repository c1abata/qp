#!/usr/bin/env python3
"""
lib/bluetooth_alert.py

Send alert Bluetooth (OBEX file push).
Fallback out-of-band.
"""

import subprocess
import tempfile
import logging
import os

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

        path = ""
        try:
            # OBEX expects a real file path, so use a named temp file and remove it after send.
            with tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8") as f:
                f.write(message)
                path = f.name

            subprocess.run(
                ["bluetoothctl", "connect", self.mac],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )

            proc = subprocess.run(
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

            if proc.returncode != 0:
                log.warning("BT send failed: obexftp exit code %s", proc.returncode)
                return False

            log.info("BT send TO %s", self.mac)
            return True

        except Exception as e:
            log.warning("BT send failed: %s", e)
            return False
        finally:
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass

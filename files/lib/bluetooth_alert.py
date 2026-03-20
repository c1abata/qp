import subprocess
import logging
import time

log = logging.getLogger(__name__)


class BluetoothAlerter:
    def __init__(self, mac=None, retries=3):
        self.mac = mac
        self.retries = retries

    def _run(self, cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
        except Exception:
            return ""

    def is_device_connected(self):
        if not self.mac:
            return False

        out = self._run(["hcitool", "con"])
        return self.mac.lower() in out.lower()

    def send(self, message):
        if not self.mac:
            return False

        for _ in range(self.retries):
            try:
                subprocess.run(
                    ["bluetoothctl", "connect", self.mac],
                    timeout=5
                )
                time.sleep(1)

                subprocess.run(
                    ["bluetooth-sendto", "--device", self.mac, "/tmp/net_alert.txt"],
                    timeout=5
                )
                return True
            except Exception as e:
                log.warning(f"Bluetooth send failed: {e}")
                time.sleep(2)

        return False
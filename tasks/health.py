import socket
import subprocess
import logging

from lib.bluetooth_alert import BluetoothAlerter

log = logging.getLogger(__name__)
AREA = "HEALTH"


def has_ip():
    out = subprocess.getoutput("ip -4 addr show")
    return "inet " in out


def has_internet(target="1.1.1.1"):
    try:
        socket.create_connection((target, 53), timeout=3)
        return True
    except Exception:
        return False


def run(cfg, out_dir, alerter):
    findings = []

    bt_mac = cfg.get("Bluetooth", "device_mac", fallback=None)
    bt = BluetoothAlerter(bt_mac)

    ip_ok = has_ip()
    net_ok = has_internet(cfg["General"]["target_external"])

    if not ip_ok:
        msg = "❌ Nessun IP sulle interfacce"
        findings.append(msg)
        alerter.finding(AREA, msg, level="critical")
        bt.send(msg)

    if not net_ok:
        msg = "❌ Internet NON raggiungibile"
        findings.append(msg)
        alerter.finding(AREA, msg, level="critical")
        bt.send(msg)

    return findings
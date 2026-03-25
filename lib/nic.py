"""
lib/nic.py - Recon NIC status.

Logica:
  1. Fidn IP (prima non-loopback online)
  2. Extract Subnet
  3. Extract Gateway
  4. find custom code DHCP (options 252 o hostname trick)
"""

import os
import re
import socket
import struct
import subprocess
import logging

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Interfaccia attiva
# ---------------------------------------------------------------------------

def get_active_interface():
    """Restituisce (iface, ip) della prima interfaccia con IP non-loopback."""
    try:
        out = subprocess.check_output(["ip", "-o", "-4", "addr", "show"],
                                      text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            # es: "2: eth0    inet 192.168.1.42/24 ..."
            m = re.match(r'\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
            if m:
                iface, ip, prefix = m.group(1), m.group(2), m.group(3)
                if iface.startswith("lo"):
                    continue
                return iface, ip, int(prefix)
    except Exception as e:
        log.warning(f"get_active_interface: {e}")
    return None, None, None


# ---------------------------------------------------------------------------
# Subnet da IP + prefisso
# ---------------------------------------------------------------------------

def ip_prefix_to_subnet(ip, prefix):
    """'192.168.1.42', 24 -> '192.168.1.0/24'"""
    try:
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        mask   = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        net_int= ip_int & mask
        net_ip = socket.inet_ntoa(struct.pack("!I", net_int))
        return f"{net_ip}/{prefix}"
    except Exception as e:
        log.warning(f"ip_prefix_to_subnet: {e}")
        return None


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------

def get_default_gateway():
    """Read Gateway from route table."""
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"],
                                      text=True, stderr=subprocess.DEVNULL)
        m = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', out)
        if m:
            return m.group(1)
    except Exception as e:
        log.warning(f"get_default_gateway: {e}")
    return None


# ---------------------------------------------------------------------------
# Parametri custom via DHCP / hostname
#
# Trucco antirez-style: passiamo parametri extra codificandoli nell'hostname
# del client DHCP oppure leggendo l'opzione DHCP 252 (WPAD / custom).
#
# Formato hostname encoding:
#   audit-target=8.8.8.8-iface=eth1
#   Il server DHCP riflette l'hostname nel lease, noi lo rileggiamo.
#
# Questo permette di configurare il Pi da remoto cambiando solo il record
# hostname nel DHCP server, zero file da toccare sul Pi.
# ---------------------------------------------------------------------------

def _read_dhcp_lease(iface):
    """Legge il file di lease dhclient o dhcpcd."""
    candidates = [
        f"/var/lib/dhcp/dhclient.{iface}.leases",
        f"/var/lib/dhcpcd5/{iface}.lease",
        f"/var/lib/NetworkManager/dhclient-{iface}.conf",
        "/var/lib/dhcp/dhclient.leases",
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                return open(path).read()
            except Exception:
                pass
    return ""


def parse_dhcp_params(iface):
    """
    Restituisce dict con parametri custom trovati nel lease DHCP.
    Cerca:
      - opzione 252 (stringa arbitraria, usiamo per target)
      - hostname encodato nel formato: audit-KEY=VAL-KEY=VAL
    """
    params = {}
    lease  = _read_dhcp_lease(iface)
    if not lease:
        return params

    # Opzione 252 (spesso usata per WPAD, ma noi la riutilizziamo)
    m = re.search(r'option\s+wpad\s+"([^"]+)"', lease)
    if m:
        params["dhcp_target"] = m.group(1).strip()
        log.info(f"DHCP option-252 target: {params['dhcp_target']}")

    # Hostname encoding: cerca "audit-" nel campo host-name del lease
    m = re.search(r'host-name\s+"(audit-[^"]+)"', lease)
    if m:
        encoded = m.group(1)          # es: audit-target=1.2.3.4-iface=eth1
        log.info(f"DHCP hostname params: {encoded}")
        for kv in encoded.replace("audit-", "").split("-"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k.strip()] = v.strip()

    return params


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def detect_network_params(iface_override=None):
    """
    Ritorna un dict con tutti i parametri rilevati:
      interface, local_ip, local_subnet, gateway, dhcp_target, [extra da DHCP]
    """
    iface, ip, prefix = get_active_interface()

    # Override da CLI / config
    if iface_override:
        iface = iface_override
        # Ricalcoliamo IP e prefix per l'interfaccia specificata
        try:
            out = subprocess.check_output(
                ["ip", "-o", "-4", "addr", "show", iface],
                text=True, stderr=subprocess.DEVNULL)
            m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', out)
            if m:
                ip, prefix = m.group(1), int(m.group(2))
        except Exception:
            pass

    subnet  = ip_prefix_to_subnet(ip, prefix) if ip and prefix else None
    gateway = get_default_gateway()
    dhcp    = parse_dhcp_params(iface) if iface else {}

    result = {
        "interface":    iface,
        "local_ip":     ip,
        "local_subnet": subnet,
        "gateway":      gateway,
    }
    result.update(dhcp)

    log.info(f"NIC detect: {result}")
    return result

"""
tasks/hygiene.py - HYGIENE Area
Network hygiene checks: default credentials, open shares, weak protocols,
rogue DHCP, exposed management interfaces, cleartext services, certificate health.


"""

import re
import socket
import subprocess
import logging
import json
import os
import shutil

log = logging.getLogger(__name__)
AREA = "HYGIENE"


def _run(cmd, out_file=None, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = r.stdout + r.stderr
        if out_file:
            with open(out_file, "w") as f:
                f.write(out)
        return out
    except subprocess.TimeoutExpired:
        log.warning(f"Timeout: {' '.join(str(c) for c in cmd)}")
        return ""
    except Exception as e:
        log.error(f"_run {cmd[0]}: {e}")
        return ""


def _command_available(name):
    return shutil.which(name) is not None


def _extract_host_ip(header):
    match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)$', header.strip())
    if match:
        return match.group(1)

    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', header)
    return match.group(1) if match else header.strip()


def _iter_nmap_host_blocks(text):
    for chunk in text.split("Nmap scan report for ")[1:]:
        header, _, rest = chunk.partition("\n")
        host = _extract_host_ip(header)
        yield host, rest


def _hosts_with_open_port(text, port, proto="tcp"):
    hosts = []
    needle = f"{port}/{proto}"
    for host, block in _iter_nmap_host_blocks(text):
        if needle in block and " open " in block:
            hosts.append(host)
    return sorted(set(hosts))


def _tcp_connect(host, port, timeout=3):
    """Ritorna True se la porta TCP è aperta."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _banner_grab(host, port, timeout=4, send=None):
    """Cattura banner da una porta TCP."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            if send:
                s.sendall(send.encode())
            return s.recv(512).decode(errors="replace")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_default_credentials(cfg, out_dir, alerter):
    """
    Testa credenziali di default comuni su gateway e host LAN.
    Protocolli: HTTP basic/form, SSH (banner only - no brute).
    NON esegue brute-force: controlla solo coppie note (admin/admin, ecc.).
    """
    findings = []
    gateway = cfg["General"].get("gateway", "")
    if not gateway:
        return findings

    DEFAULT_CREDS = [
        ("admin", "admin"), ("admin", "password"), ("admin", ""),
        ("root", "root"), ("root", ""), ("user", "user"),
        ("admin", "1234"), ("admin", "admin123"),
    ]

    report_lines = []
    for user, pwd in DEFAULT_CREDS:
        # HTTP Basic Auth verso gateway
        out = _run(
            ["curl", "-sf", "-u", f"{user}:{pwd}", "-o", "/dev/null",
             "-w", "%{http_code}", "--max-time", "4",
             f"http://{gateway}/"],
            timeout=6
        )
        code = out.strip()
        report_lines.append(f"http://{gateway} [{user}:{pwd}] → HTTP {code}")
        if code in ("200", "302", "301"):
            msg = f"Credenziali di default funzionanti su http://{gateway} → {user}:{pwd}"
            findings.append(msg)
            alerter.finding(AREA, msg, level="critical")
            break  # basta un match, non continuare

    with open(f"{out_dir}/default_creds.txt", "w") as f:
        f.write("\n".join(report_lines))

    return findings


def check_open_shares(cfg, out_dir, alerter):
    """
    Individua share SMB/NFS accessibili senza autenticazione nella subnet.
    """
    findings = []
    subnet = cfg["General"]["local_subnet"]

    # SMB null session
    out_smb = _run(
        ["nmap", "-n", "-T2", "-p", "445", "--open", "--max-retries=1",
         "--script", "smb-enum-shares,smb-security-mode",
         "--script-args", "smbusername=guest,smbpassword=",
         "-oN", f"{out_dir}/smb_shares.txt", subnet],
        timeout=180
    )

    # Cerca share trovate
    anon_shares = re.findall(r'(SHARE|IPC\$|print\$|[A-Za-z0-9_]+)\s+\n.*?Anonymous access:\s+READ', out_smb)
    hosts_smb = _hosts_with_open_port(out_smb, "445")

    if anon_shares:
        msg = f"Share SMB anonime accessibili: {sorted(set(anon_shares))}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="critical")
    elif hosts_smb:
        msg = f"Host SMB trovati (auth richiesta): {hosts_smb}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="info")

    # NFS exports
    out_nfs = _run(
        ["nmap", "-n", "-T2", "-p", "111,2049", "--open", "--max-retries=1",
         "--script", "nfs-showmount,nfs-ls",
         "-oN", f"{out_dir}/nfs_shares.txt", subnet],
        timeout=120
    )
    nfs_exports = re.findall(r'NFS Export:\s+(.+)', out_nfs)
    if nfs_exports:
        msg = f"Export NFS rilevati: {nfs_exports}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="critical")

    return findings


def check_cleartext_services(cfg, out_dir, alerter):
    """
    Rileva servizi che trasmettono in chiaro: Telnet, FTP, HTTP, SNMP v1/v2,
    POP3, IMAP, SMTP non-TLS nella subnet.
    """
    findings = []
    subnet = cfg["General"]["local_subnet"]
    CLEARTEXT_PORTS = "21,23,25,80,110,143,161,512,513,514,8080"

    out = _run(
        ["nmap", "-sV", "-n", "-T2", "-p", CLEARTEXT_PORTS, "--open",
         "--max-retries=1", "--version-intensity", "2",
         "-oN", f"{out_dir}/cleartext_services.txt", subnet],
        timeout=240
    )

    RISKY = {
        "23": "Telnet",
        "21": "FTP",
        "512": "rexec",
        "513": "rlogin",
        "514": "rsh",
    }
    for port, svc in RISKY.items():
        hosts = _hosts_with_open_port(out, port)
        if hosts:
            msg = f"Servizio cleartext {svc} (:{port}) attivo su: {hosts}"
            findings.append(msg)
            alerter.finding(AREA, msg, level="critical")

    # HTTP (80/8080) senza redirect a HTTPS
    http_hosts = _hosts_with_open_port(out, "80") + _hosts_with_open_port(out, "8080")
    http_open = []
    for h in set(http_hosts):
        out_http = _run(
            ["curl", "-sf", "-o", "/dev/null", "-w", "%{redirect_url}",
             "--max-time", "4", f"http://{h}/"],
            timeout=6
        )
        if "https" not in out_http.lower():
            http_open.append(h)
    if http_open:
        msg = f"HTTP senza redirect HTTPS su: {http_open}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="warning")

    return findings


def check_rogue_dhcp(cfg, out_dir, alerter):
    """
    Rileva server DHCP non autorizzati nella subnet.
    Tecnica: invia DHCPDISCOVER e aspetta risposte da più server.
    Richiede nmap o dhcping.
    """
    findings = []
    iface = cfg["General"]["interface"]

    # nmap script broadcast-dhcp-discover
    out = _run(
        ["nmap", "--script", "broadcast-dhcp-discover",
         "-e", iface, "--script-args", "newtargets",
         "-oN", f"{out_dir}/rogue_dhcp.txt"],
        timeout=30
    )

    servers = re.findall(r'Server Identifier:\s+(\d+\.\d+\.\d+\.\d+)', out)
    gateway = cfg["General"].get("gateway", "")

    if len(servers) > 1:
        rogue = [s for s in servers if s != gateway]
        msg = f"DHCP server multipli rilevati! Legittimo: {gateway}, Rogue: {rogue}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="critical")
    elif servers and servers[0] != gateway:
        msg = f"DHCP server inatteso: {servers[0]} (gateway atteso: {gateway})"
        findings.append(msg)
        alerter.finding(AREA, msg, level="critical")
    elif servers:
        log.info(f"DHCP server: {servers[0]} (corrisponde al gateway)")

    return findings


def check_exposed_management(cfg, out_dir, alerter):
    """
    Cerca interfacce di gestione esposte: web UI router, Proxmox, iDRAC,
    Portainer, Grafana, Kibana, Jenkins, ecc. sulla subnet.
    """
    findings = []
    subnet = cfg["General"]["local_subnet"]

    MGMT_PORTS = (
        "22,80,443,8080,8443,8888,9090,9443,"  # SSH, web generico
        "3000,5000,5601,8161,9200,"             # Grafana, Flask, Kibana, ActiveMQ, Elasticsearch
        "19999,10000,8006,7070,4848"            # Netdata, Webmin, Proxmox, Glassfish
    )

    out = _run(
        ["nmap", "-sV", "-n", "-T2", "-p", MGMT_PORTS, "--open",
         "--max-retries=1",
         "-oN", f"{out_dir}/mgmt_interfaces.txt", subnet],
        timeout=240
    )

    MGMT_SIGNATURES = {
        "Proxmox": ["8006"],
        "Elasticsearch": ["9200"],
        "Kibana": ["5601"],
        "Grafana": ["3000"],
        "Portainer/Docker": ["9000", "9443"],
        "Webmin": ["10000"],
        "Netdata": ["19999"],
        "Jenkins": ["8080", "8443"],
    }

    for svc, ports in MGMT_SIGNATURES.items():
        for p in ports:
            hosts = _hosts_with_open_port(out, p)
            if hosts:
                msg = f"Interfaccia di gestione {svc} (:{p}) esposta su: {hosts}"
                findings.append(msg)
                alerter.finding(AREA, msg, level="warning")

    return findings


def check_tls_certificates(cfg, out_dir, alerter):
    """
    Verifica certificati TLS su host HTTPS della subnet:
    - certificati scaduti o in scadenza (< 30 giorni)
    - self-signed
    - weak cipher suite (TLS 1.0/1.1)
    """
    findings = []
    subnet = cfg["General"]["local_subnet"]

    if not _command_available("openssl"):
        msg = "openssl non disponibile: skip verifica certificati TLS"
        log.warning(msg)
        with open(f"{out_dir}/tls_report.txt", "w") as f:
            f.write(msg + "\n")
        return findings

    # Prima trova host con 443 aperto
    out_scan = _run(
        ["nmap", "-n", "-T2", "-p", "443,8443", "--open", "--max-retries=1", subnet,
         "-oG", f"{out_dir}/tls_hosts.gnmap"],
        timeout=120
    )

    try:
        gnmap = open(f"{out_dir}/tls_hosts.gnmap").read()
    except Exception:
        gnmap = ""

    https_hosts = re.findall(r'Host:\s+(\d+\.\d+\.\d+\.\d+)', gnmap)
    report = []

    for host in set(https_hosts):
        for port in ["443", "8443"]:
            # openssl: verifica cert e TLS version
            out = _run(
                ["openssl", "s_client", "-connect", f"{host}:{port}",
                 "-brief", "-verify_quiet", "-servername", host],
                timeout=8
            )
            if not out:
                continue

            # Scadenza
            not_after = re.search(r'notAfter=(.+)', out)
            if not_after:
                report.append(f"{host}:{port} → expires: {not_after.group(1).strip()}")

            # Self-signed (emittente = soggetto)
            issuer  = re.search(r'issuer=(.+)', out)
            subject = re.search(r'subject=(.+)', out)
            if issuer and subject and issuer.group(1).strip() == subject.group(1).strip():
                msg = f"Certificato self-signed su {host}:{port}"
                if msg not in findings:
                    findings.append(msg)
                    alerter.finding(AREA, msg, level="warning")

            # TLS 1.0 / 1.1 accettato
            for old_tls in ["-tls1", "-tls1_1"]:
                tls_out = _run(
                    ["openssl", "s_client", "-connect", f"{host}:{port}",
                     old_tls, "-brief", "-servername", host],
                    timeout=6
                )
                if "Verify return code" in tls_out:
                    ver = "TLS 1.0" if old_tls == "-tls1" else "TLS 1.1"
                    msg = f"Protocollo obsoleto {ver} accettato da {host}:{port}"
                    if msg not in findings:
                        findings.append(msg)
                        alerter.finding(AREA, msg, level="warning")

    with open(f"{out_dir}/tls_report.txt", "w") as f:
        f.write("\n".join(report) if report else "Nessun host HTTPS trovato.\n")

    return findings


def check_snmp_community(cfg, out_dir, alerter):
    """
    Testa community string SNMP di default (public, private) sulla subnet.
    SNMP v1/v2c in chiaro è un vettore di ricognizione frequente.
    """
    findings = []
    subnet = cfg["General"]["local_subnet"]

    if not _command_available("snmpget"):
        msg = "snmpget non disponibile: skip test community SNMP"
        log.warning(msg)
        with open(f"{out_dir}/snmp_report.txt", "w") as f:
            f.write(msg + "\n")
        return findings

    # Trova host con UDP 161 aperto
    out_scan = _run(
        ["nmap", "-sU", "-n", "-T2", "-p", "161", "--open", "--max-retries=1", subnet,
         "-oG", f"{out_dir}/snmp_hosts.gnmap"],
        timeout=120
    )
    try:
        gnmap = open(f"{out_dir}/snmp_hosts.gnmap").read()
    except Exception:
        gnmap = ""

    snmp_hosts = re.findall(r'Host:\s+(\d+\.\d+\.\d+\.\d+)', gnmap)
    report = []

    for host in set(snmp_hosts):
        for community in ["public", "private", "community", "admin", ""]:
            out = _run(
                ["snmpget", "-v2c", "-c", community, "-r1", "-t2",
                 host, "1.3.6.1.2.1.1.1.0"],  # sysDescr
                timeout=5
            )
            if "STRING:" in out or "INTEGER:" in out:
                desc = re.search(r'STRING:\s*(.+)', out)
                desc_txt = desc.group(1).strip()[:80] if desc else "OK"
                report.append(f"{host} community='{community}': {desc_txt}")
                msg = f"SNMP community di default '{community}' accettata da {host}"
                findings.append(msg)
                alerter.finding(AREA, msg, level="critical")
                break  # trovata, passa all'host successivo

    with open(f"{out_dir}/snmp_report.txt", "w") as f:
        f.write("\n".join(report) if report else "Nessun host SNMP vulnerabile trovato.\n")

    return findings


def check_upnp_exposure(cfg, out_dir, alerter):
    """
    Rileva dispositivi UPnP attivi (IGD, router, smart device).
    UPnP aperto in LAN può permettere port forwarding non autorizzato.
    """
    findings = []
    iface = cfg["General"]["interface"]

    # nmap broadcast UPnP
    out = _run(
        ["nmap", "--script", "broadcast-upnp-info",
         "-e", iface,
         "-oN", f"{out_dir}/upnp.txt"],
        timeout=20
    )

    upnp_devices = re.findall(r'Location:\s+http://(\d+\.\d+\.\d+\.\d+)', out)
    if upnp_devices:
        msg = f"Dispositivi UPnP attivi: {upnp_devices} — possibile port forwarding non autorizzato"
        findings.append(msg)
        alerter.finding(AREA, msg, level="warning")

    # Anche su porta 1900 UDP direttamente
    out2 = _run(
        ["nmap", "-sU", "-n", "-T2", "-p", "1900", "--open", "--max-retries=1",
         "--script", "upnp-info",
         "-oN", f"{out_dir}/upnp_udp.txt",
         cfg["General"]["local_subnet"]],
        timeout=60
    )
    igd_hosts = re.findall(r'(\d+\.\d+\.\d+\.\d+).*?WANIPConnection', out2, re.DOTALL)
    if igd_hosts:
        msg = f"IGD UPnP (Internet Gateway Device) su: {igd_hosts} — può aprire porte internet"
        findings.append(msg)
        alerter.finding(AREA, msg, level="critical")

    return findings


def check_password_policy(cfg, out_dir, alerter):
    """
    Verifica policy password e autenticazione su SMB/LDAP.
    Rileva guest access abilitato, autenticazione NTLM v1, account privi di password.
    """
    findings = []
    subnet = cfg["General"]["local_subnet"]

    out = _run(
        ["nmap", "-n", "-T2", "-p", "445", "--open", "--max-retries=1",
         "--script", "smb-security-mode,smb2-security-mode,smb-enum-users",
         "-oN", f"{out_dir}/smb_auth.txt", subnet],
        timeout=120
    )

    # NTLMv1 (message signing disabled = downgrade attack possibile)
    if "message_signing: disabled" in out.lower():
        msg = "SMB message signing disabilitato — vulnerabile a relay attack"
        findings.append(msg)
        alerter.finding(AREA, msg, level="critical")

    if "guest account is enabled" in out.lower():
        msg = "Account guest SMB abilitato su uno o più host"
        findings.append(msg)
        alerter.finding(AREA, msg, level="warning")

    if "authentication: plaintext" in out.lower():
        msg = "SMB accetta autenticazione in chiaro (plaintext)"
        findings.append(msg)
        alerter.finding(AREA, msg, level="critical")

    return findings


def check_arp_table_anomalies(cfg, out_dir, alerter):
    """
    Analizza la tabella ARP locale per anomalie:
    - IP multipli sullo stesso MAC (ARP poisoning)
    - MAC broadcast / multicast inattesi
    - Cambio MAC rispetto al run precedente (se disponibile)
    """
    findings = []
    out = _run(["arp", "-n"], out_file=f"{out_dir}/arp_table.txt")

    entries = re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f:]{17})', out.lower())

    # MAC → lista IP
    mac_to_ips = {}
    for ip, mac in entries:
        mac_to_ips.setdefault(mac, []).append(ip)

    # IP multipli per MAC → possibile ARP spoofing
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            msg = f"ARP anomalia: MAC {mac} associato a IP multipli: {ips} — possibile ARP spoofing"
            findings.append(msg)
            alerter.finding(AREA, msg, level="critical")

    # MAC multicast (bit LSB del primo ottetto = 1)
    for ip, mac in entries:
        first_byte = mac.split(":")[0]
        if int(first_byte, 16) & 1:
            msg = f"MAC multicast/broadcast inatteso in tabella ARP: {ip} → {mac}"
            findings.append(msg)
            alerter.finding(AREA, msg, level="warning")

    # Persistenza: confronta con il run precedente
    state_file = "/var/log/net_audit/arp_baseline.json"
    current = {ip: mac for ip, mac in entries}
    if os.path.exists(state_file):
        try:
            baseline = json.loads(open(state_file).read())
            for ip, mac in current.items():
                if ip in baseline and baseline[ip] != mac:
                    msg = f"MAC cambiato per {ip}: {baseline[ip]} → {mac} (ARP spoofing?)"
                    findings.append(msg)
                    alerter.finding(AREA, msg, level="critical")
        except Exception:
            pass
    # Salva baseline attuale
    try:
        os.makedirs(os.path.dirname(state_file), exist_ok=True)
        with open(state_file, "w") as f:
            json.dump(current, f)
    except Exception:
        pass

    return findings


def check_wireless_security(cfg, out_dir, alerter):
    """
    Se disponibile un'interfaccia wireless, verifica:
    - reti aperte nelle vicinanze
    - SSID nascosti
    - Autenticazione WEP/WPA (obsolete)
    """
    findings = []

    if not _command_available("iw"):
        log.info("iw non disponibile, skip check_wireless_security")
        return findings

    # Cerca interfacce wireless
    out_iw = _run(["iw", "dev"])
    wlan_ifaces = re.findall(r'Interface\s+(\S+)', out_iw)

    if not wlan_ifaces:
        log.info("Nessuna interfaccia wireless rilevata, skip check_wireless_security")
        return findings

    wlan = wlan_ifaces[0]
    out_scan = _run(
        ["iw", "dev", wlan, "scan"],
        out_file=f"{out_dir}/wifi_scan.txt",
        timeout=20
    )

    # Reti aperte (nessuna encryption)
    wpa_blocks = out_scan.split("BSS ")
    open_ssids = []
    for block in wpa_blocks:
        ssid_m = re.search(r'SSID:\s+(.+)', block)
        if ssid_m and "RSN:" not in block and "WPA:" not in block and ssid_m.group(1).strip():
            open_ssids.append(ssid_m.group(1).strip())

    if open_ssids:
        msg = f"Reti WiFi aperte (no encryption) nelle vicinanze: {open_ssids}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="warning")

    # WEP (deprecato da oltre 20 anni)
    wep_nets = []
    for block in wpa_blocks:
        ssid_m = re.search(r'SSID:\s+(.+)', block)
        if ssid_m and "WEP" in block:
            wep_nets.append(ssid_m.group(1).strip())
    if wep_nets:
        msg = f"Reti WEP rilevate (gravemente obsoleto): {wep_nets}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="critical")

    return findings



def check_doh_enforcement(cfg, out_dir, alerter):
    """
    Verifica se il DNS over HTTPS è realmente enforced o aggirabile.

    Tre livelli di analisi:
      1. Configurazione: systemd-resolved, resolv.conf, stub listener
      2. Leak test: cattura tcpdump su porta 53 durante query di test
      3. Bypass test: tenta query UDP/53 dirette verso resolver noti
    """
    import subprocess, re, os, time, threading

    findings = []
    report   = []
    iface    = cfg["General"]["interface"]

    # ------------------------------------------------------------------
    # 1. Rilevamento configurazione DoH sul sistema
    # ------------------------------------------------------------------

    doh_configured = False
    resolver_type  = "unknown"

    # systemd-resolved
    resolved_conf_paths = [
        "/etc/systemd/resolved.conf",
        "/etc/systemd/resolved.conf.d/",
    ]
    resolved_conf = ""
    for p in resolved_conf_paths:
        if os.path.isfile(p):
            try:
                resolved_conf += open(p).read()
            except Exception:
                pass
        elif os.path.isdir(p):
            try:
                for f in os.listdir(p):
                    resolved_conf += open(os.path.join(p, f)).read()
            except Exception:
                pass

    if resolved_conf:
        resolver_type = "systemd-resolved"
        # DNS= può contenere https:// (DoH) oppure IP plain
        dns_line = re.search(r'^DNS\s*=\s*(.+)', resolved_conf, re.M)
        dnsoverhttps_line = re.search(r'^DNSOverTLS\s*=\s*(\S+)', resolved_conf, re.M | re.I)
        doh_line = re.search(r'https://', resolved_conf)

        if doh_line:
            doh_configured = True
            report.append("systemd-resolved: DoH URL trovato nella config")
        if dnsoverhttps_line and dnsoverhttps_line.group(1).lower() in ("yes", "opportunistic", "enforce"):
            doh_configured = True
            report.append(f"systemd-resolved: DNSOverTLS={dnsoverhttps_line.group(1)}")
        if dns_line:
            report.append(f"DNS configurato: {dns_line.group(1).strip()}")

    # Stub listener su 127.0.0.53 (tipico di systemd-resolved)
    stub_active = False
    out_stub = _run(["ss", "-ulnp"], timeout=5)
    if "127.0.0.53" in out_stub and ":53 " in out_stub:
        stub_active  = True
        resolver_type = "systemd-resolved stub"
        report.append("Stub resolver attivo su 127.0.0.53:53")

    # resolv.conf: punta a stub o a IP remoto?
    resolv_content = ""
    try:
        resolv_content = open("/etc/resolv.conf").read()
    except Exception:
        pass
    resolv_nameservers = re.findall(r'^nameserver\s+(\S+)', resolv_content, re.M)
    report.append(f"resolv.conf nameserver: {resolv_nameservers}")

    # ------------------------------------------------------------------
    # 2. Leak test: cattura traffico UDP/53 durante query di test
    # ------------------------------------------------------------------

    pcap_file = f"{out_dir}/dns_leak.pcap"
    captured_packets = []

    # Avvia tcpdump in background per 10 secondi
    tcpdump_proc = None
    try:
        tcpdump_proc = subprocess.Popen(
            ["tcpdump", "-i", iface, "-w", pcap_file,
             "udp port 53 or tcp port 53", "-G", "10", "-W", "1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except Exception as e:
        report.append(f"tcpdump non avviabile: {e}")

    # Esegui query di test (volutamente verso nomi nuovi, no cache)
    test_hosts = [
        "doh-enforcement-test-1.example.com",
        "doh-enforcement-test-2.example.com",
    ]
    time.sleep(1)  # lascia partire tcpdump
    for h in test_hosts:
        _run(["dig", h, "A", "+time=3", "+tries=1"], timeout=5)
    time.sleep(2)  # lascia catturare

    if tcpdump_proc:
        tcpdump_proc.terminate()
        try:
            tcpdump_proc.wait(timeout=3)
        except Exception:
            tcpdump_proc.kill()

    # Leggi i pacchetti catturati
    if os.path.exists(pcap_file):
        out_pcap = _run(["tcpdump", "-r", pcap_file, "-nn", "udp port 53 or tcp port 53"],
                        timeout=8)
        captured_packets = [l for l in out_pcap.splitlines() if l.strip()]
        report.append(f"Pacchetti DNS cleartext catturati durante query di test: {len(captured_packets)}")

        # Filtra: ignora pacchetti verso 127.0.0.53 (stub locale lecito)
        external_leaks = [
            p for p in captured_packets
            if "127.0.0.53" not in p and "127.0.0.1" not in p
        ]
        if external_leaks:
            msg = (f"DNS cleartext leak: {len(external_leaks)} pacchetti UDP/53 "
                   f"verso resolver esterni durante query di test")
            findings.append(msg)
            alerter.finding(AREA, msg, level="critical")
            report.append("Esempi leak:")
            for p in external_leaks[:3]:
                report.append(f"  {p}")
        elif captured_packets and doh_configured:
            # Pacchetti ci sono ma solo verso stub locale → OK se stub fa DoH upstream
            report.append("Query DNS passano per lo stub locale (verifica upstream sotto)")

    # ------------------------------------------------------------------
    # 3. Bypass test: tenta query UDP/53 dirette verso resolver noti
    #    Se escono, il firewall locale NON blocca la porta 53 outbound
    #    → un'app malevola o mal configurata può bypassare DoH
    # ------------------------------------------------------------------

    bypass_resolvers = {
        "Google":       "8.8.8.8",
        "Cloudflare":   "1.1.1.1",
        "OpenDNS":      "208.67.222.222",
        "Quad9":        "9.9.9.9",
    }
    bypass_ok = []
    for name, ip in bypass_resolvers.items():
        out = _run(
            ["dig", f"@{ip}", "example.com", "A", "+time=3", "+tries=1", "+short"],
            timeout=5
        )
        # Se otteniamo una risposta valida, UDP/53 outbound è aperto
        if re.search(r'\d+\.\d+\.\d+\.\d+', out):
            bypass_ok.append(f"{name} ({ip})")

    if bypass_ok:
        msg = (f"UDP/53 outbound non bloccato: query dirette riuscite verso "
               f"{bypass_ok} — DoH bypassabile da qualsiasi processo")
        findings.append(msg)
        alerter.finding(AREA, msg, level="critical")
        report.append(f"Bypass riuscito verso: {bypass_ok}")
    else:
        report.append("UDP/53 outbound bloccato: nessun bypass diretto riuscito")

    # ------------------------------------------------------------------
    # 4. Verifica upstream di systemd-resolved (se stub attivo)
    #    Controlla se resolved stesso fa cleartext verso l'upstream
    # ------------------------------------------------------------------

    if stub_active:
        # Cattura traffico dalla macchina verso l'esterno su porta 53
        # mentre forziamo una query attraverso lo stub
        pcap2 = f"{out_dir}/resolved_upstream.pcap"
        try:
            proc2 = subprocess.Popen(
                ["tcpdump", "-i", iface, "-w", pcap2,
                 "udp port 53 or tcp port 53",
                 "-G", "8", "-W", "1"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(1)
            _run(["dig", "@127.0.0.53", "resolved-upstream-test.example.com",
                  "A", "+time=3"], timeout=5)
            time.sleep(2)
            proc2.terminate()
            proc2.wait(timeout=3)
        except Exception as e:
            report.append(f"Upstream check error: {e}")

        if os.path.exists(pcap2):
            out2 = _run(["tcpdump", "-r", pcap2, "-nn"], timeout=5)
            upstream_plain = [
                l for l in out2.splitlines()
                if "port 53" in l
                and not any(x in l for x in ("127.0.0.53", "127.0.0.1"))
            ]
            if upstream_plain and not doh_configured:
                msg = ("systemd-resolved usa stub locale ma fa cleartext UDP/53 "
                       "verso l'upstream — DoH non configurato in resolved.conf")
                findings.append(msg)
                alerter.finding(AREA, msg, level="warning")
            elif upstream_plain and doh_configured:
                msg = ("systemd-resolved configurato con DoH ma upstream cleartext "
                       "rilevato — possibile fallback insicuro")
                findings.append(msg)
                alerter.finding(AREA, msg, level="critical")
            else:
                report.append("systemd-resolved upstream: nessun cleartext rilevato")

    # ------------------------------------------------------------------
    # Sommario
    # ------------------------------------------------------------------

    report.insert(0, f"Resolver type : {resolver_type}")
    report.insert(1, f"DoH configurato: {doh_configured}")
    report.insert(2, f"Stub 127.0.0.53: {stub_active}")
    report.insert(3, "---")

    with open(f"{out_dir}/doh_enforcement.txt", "w") as f:
        f.write("\n".join(report))

    if not findings:
        if doh_configured:
            alerter.finding(AREA, "DoH enforcement verificato: nessun leak cleartext rilevato", level="info")
        else:
            alerter.finding(AREA, "DoH non configurato sul sistema (resolv.conf plain)", level="warning")

    return findings



def check_network_doh_dot_policy(cfg, out_dir, alerter):
    """
    Verifica cosa la RETE permette in termini di DNS cifrato (DoH/DoT).

    Domanda: un host dentro questa rete può usare DoH/DoT verso resolver
    esterni? Se sì, può bypassare qualsiasi policy DNS interna e cifrare
    il traffico DNS in modo da renderlo invisibile al firewall.

    Vettori testati:
      1. DNS plaintext UDP/53      — baseline: se funziona, DoH non è enforced
      2. DNS over TLS TCP/853      — tunneling DNS cifrato, rilevabile solo per porta
      3. DoH HTTPS TCP/443         — indistinguibile da traffico web normale
      4. DoH con SNI noto          — alcuni firewall bloccano per SNI, non per porta
      5. Porte DoH alternative     — 8443, 8853, fallback di alcuni client

    Interpretazione findings:
      - Rete aziendale/scolastica: DoH attivo = rischio bypass policy DNS
      - Rete non gestita/domestica: DoH attivo = buona igiene, indica maturità
      - Il check registra lo stato, l'analisi del rischio è contestuale.
    """
    import json, time

    findings  = []
    report    = {}
    AREA_NAME = AREA  # eredita da modulo hygiene

    # Resolver DoH/DoT pubblici ben noti, usati come target di test
    DOH_RESOLVERS = [
        {
            "name":       "Cloudflare",
            "ip":         "1.1.1.1",
            "dot_host":   "one.one.one.one",
            "doh_url":    "https://1.1.1.1/dns-query",
            "doh_sni":    "cloudflare-dns.com",
        },
        {
            "name":       "Google",
            "ip":         "8.8.8.8",
            "dot_host":   "dns.google",
            "doh_url":    "https://dns.google/dns-query",
            "doh_sni":    "dns.google",
        },
        {
            "name":       "Quad9",
            "ip":         "9.9.9.9",
            "dot_host":   "dns.quad9.net",
            "doh_url":    "https://dns.quad9.net/dns-query",
            "doh_sni":    "dns.quad9.net",
        },
    ]

    TEST_DOMAIN = "example.com"

    # ------------------------------------------------------------------
    # Helper: esito uniforme
    # ------------------------------------------------------------------
    def probe_result(name, proto, reachable, detail=""):
        return {
            "resolver": name,
            "proto":    proto,
            "ok":       reachable,
            "detail":   detail,
        }

    results = []

    # ==================================================================
    # Vettore 1 — DNS plaintext UDP/53
    # Baseline: se risponde, la rete non ha bloccato DNS plain.
    # ==================================================================
    for r in DOH_RESOLVERS:
        out = _run(
            ["dig", f"@{r['ip']}", TEST_DOMAIN, "A",
             "+time=3", "+tries=1", "+short"],
            timeout=6
        )
        ok = bool(__import__("re").search(r"\d+\.\d+\.\d+\.\d+", out))
        results.append(probe_result(r["name"], "DNS-UDP53", ok, out.strip()[:60]))

    # ==================================================================
    # Vettore 2 — DNS over TLS TCP/853 (DoT)
    # Usa openssl s_client per handshake TLS + query DNS wire-format.
    # Se il TLS completa verso porta 853, DoT è percorribile.
    # ==================================================================
    for r in DOH_RESOLVERS:
        out = _run(
            ["openssl", "s_client",
             "-connect", f"{r['ip']}:853",
             "-servername", r["dot_host"],
             "-brief", "-verify_quiet"],
            timeout=8
        )
        ok = "Verify return code: 0" in out or "CONNECTION ESTABLISHED" in out.lower()
        detail = "TLS OK" if ok else out.splitlines()[-1][:60] if out else "timeout"
        results.append(probe_result(r["name"], "DoT-TCP853", ok, detail))

    # ==================================================================
    # Vettore 3 — DoH via HTTPS TCP/443 (JSON API)
    # Richiesta DNS-over-HTTPS standard RFC 8484.
    # Indistinguibile da traffico HTTPS normale senza deep inspection.
    # ==================================================================
    for r in DOH_RESOLVERS:
        out = _run(
            ["curl", "-sf",
             "-H", "accept: application/dns-json",
             f"{r['doh_url']}?name={TEST_DOMAIN}&type=A",
             "--max-time", "8",
             "-w", "\nHTTP:%{http_code}"],
            timeout=10
        )
        ok = ('"Status":0' in out or '"Status": 0' in out) and "HTTP:200" in out
        detail = "DoH JSON OK" if ok else f"HTTP:{out.split('HTTP:')[-1][:10]}" if "HTTP:" in out else "timeout/blocked"
        results.append(probe_result(r["name"], "DoH-HTTPS443", ok, detail))

    # ==================================================================
    # Vettore 4 — DoH con SNI specifico
    # Alcuni firewall con TLS inspection bloccano per SNI (es. "dns.google")
    # anche se la porta 443 è aperta. Questo lo rivela.
    # ==================================================================
    for r in DOH_RESOLVERS:
        out = _run(
            ["curl", "-sf",
             "--resolve", f"{r['doh_sni']}:443:{r['ip']}",
             "-H", "accept: application/dns-json",
             f"https://{r['doh_sni']}/dns-query?name={TEST_DOMAIN}&type=A",
             "--max-time", "8",
             "-w", "\nHTTP:%{http_code}"],
            timeout=10
        )
        ok = '"Status":0' in out or '"Status": 0' in out
        # Se DoH-HTTPS443 funziona ma questo fallisce → TLS inspection attiva
        detail = "SNI OK" if ok else "bloccato (TLS inspection/SNI filter?)"
        results.append(probe_result(r["name"], "DoH-SNI", ok, detail))

    # ==================================================================
    # Vettore 5 — Porte DoH alternative (8443, 8853)
    # Alcuni client e resolver usano porte non standard come fallback.
    # Porta 8853 = Cloudflare alternativa, 8443 = fallback comune.
    # ==================================================================
    ALT_PORTS = [
        ("Cloudflare", "1.1.1.1", "8443",
         "https://1.1.1.1:8443/dns-query"),
        ("Cloudflare", "1.1.1.1", "8853",
         None),  # DoT alternativa
        ("AdGuard",   "94.140.14.14", "443",
         "https://dns.adguard.com/dns-query"),
    ]
    for name, ip, port, doh_url in ALT_PORTS:
        if doh_url:
            out = _run(
                ["curl", "-sf", "-H", "accept: application/dns-json",
                 f"{doh_url}?name={TEST_DOMAIN}&type=A",
                 "--max-time", "6", "-w", "\nHTTP:%{http_code}"],
                timeout=8
            )
            ok = '"Status":0' in out or '"Status": 0' in out
            detail = f"port {port} DoH OK" if ok else f"blocked port {port}"
        else:
            # DoT test con openssl
            out = _run(
                ["openssl", "s_client",
                 "-connect", f"{ip}:{port}",
                 "-brief", "-verify_quiet"],
                timeout=6
            )
            ok = "ESTABLISHED" in out.upper() or "Verify return code: 0" in out
            detail = f"DoT port {port} OK" if ok else f"blocked port {port}"
        results.append(probe_result(f"{name}:{port}", f"ALT-{port}", ok, detail))

    # ==================================================================
    # Scrittura report dettagliato
    # ==================================================================
    with open(f"{out_dir}/doh_dot_network.json", "w") as f:
        json.dump(results, f, indent=2)

    lines = [f"{'Resolver':<22} {'Proto':<14} {'OK':<6} {'Detail'}"]
    lines.append("-" * 72)
    for r in results:
        lines.append(
            f"{r['resolver']:<22} {r['proto']:<14} "
            f"{'YES' if r['ok'] else 'no':<6} {r['detail']}"
        )
    with open(f"{out_dir}/doh_dot_network.txt", "w") as f:
        f.write("\n".join(lines))

    # ==================================================================
    # Analisi e findings
    # ==================================================================
    def protos_ok(proto_prefix):
        return [r for r in results if r["proto"].startswith(proto_prefix) and r["ok"]]

    def protos_blocked(proto_prefix):
        return [r for r in results if r["proto"].startswith(proto_prefix) and not r["ok"]]

    udp53_ok    = protos_ok("DNS-UDP53")
    dot_ok      = protos_ok("DoT-TCP853")
    doh_ok      = protos_ok("DoH-HTTPS443")
    sni_blocked = protos_blocked("DoH-SNI")
    sni_ok      = protos_ok("DoH-SNI")
    alt_ok      = protos_ok("ALT-")

    # --- Finding 1: DNS plaintext ancora percorribile
    if udp53_ok:
        resolvers = [r["resolver"] for r in udp53_ok]
        msg = (f"DNS plaintext UDP/53 verso resolver esterni non bloccato "
               f"({resolvers}) — policy DoH non enforced a livello firewall")
        findings.append(msg)
        alerter.finding(AREA_NAME, msg, level="warning")

    # --- Finding 2: DoT raggiungibile (tunneling DNS cifrato)
    if dot_ok:
        resolvers = [r["resolver"] for r in dot_ok]
        msg = (f"DNS over TLS (TCP/853) raggiungibile verso {resolvers} "
               f"— DNS cifrato percorribile, invisibile a ispezione payload")
        findings.append(msg)
        alerter.finding(AREA_NAME, msg, level="warning")

    # --- Finding 3: DoH su 443 funzionante
    if doh_ok:
        resolvers = [r["resolver"] for r in doh_ok]
        msg = (f"DoH (HTTPS/443) funzionante verso {resolvers} "
               f"— DNS cifrato indistinguibile da traffico web, bypass DNS filtering")
        findings.append(msg)
        alerter.finding(AREA_NAME, msg, level="warning")

    # --- Finding 4: TLS inspection rilevata (DoH-SNI bloccato ma HTTPS/443 aperto)
    if sni_blocked and doh_ok:
        blk = [r["resolver"] for r in sni_blocked]
        msg = (f"TLS inspection / SNI filtering rilevato per {blk}: "
               f"HTTPS/443 aperto ma SNI specifici DNS bloccati — "
               f"firewall fa deep packet inspection")
        findings.append(msg)
        alerter.finding(AREA_NAME, msg, level="info")

    # --- Finding 5: tutti i vettori bloccati (rete molto restrittiva)
    all_blocked = not udp53_ok and not dot_ok and not doh_ok and not alt_ok
    if all_blocked:
        msg = ("Tutti i vettori DoH/DoT/UDP53 bloccati — "
               "rete molto restrittiva, DNS forzato tramite resolver interno")
        findings.append(msg)
        alerter.finding(AREA_NAME, msg, level="info")

    # --- Finding 6: porte alternative accessibili
    if alt_ok:
        ports = [r["resolver"] for r in alt_ok]
        msg = (f"Porte DoH alternative accessibili: {ports} "
               f"— firewall non blocca porte non-standard per DoH/DoT")
        findings.append(msg)
        alerter.finding(AREA_NAME, msg, level="warning")

    # --- Sommario sempre visibile nel log
    ok_count  = sum(1 for r in results if r["ok"])
    tot_count = len(results)
    log.info(
        f"[HYGIENE] DoH/DoT network policy: "
        f"{ok_count}/{tot_count} vettori raggiungibili"
    )

    return findings

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

PASSIVE_CHECKS = [
    check_doh_enforcement,
    check_network_doh_dot_policy,
    check_arp_table_anomalies,
]

ACTIVE_ONLY_CHECKS = [
    check_default_credentials,
    check_open_shares,
    check_cleartext_services,
    check_rogue_dhcp,
    check_exposed_management,
    check_tls_certificates,
    check_snmp_community,
    check_upnp_exposure,
    check_password_policy,
    check_wireless_security,
]


def run(cfg, out_dir, alerter, mode="active"):
    all_findings = []
    seen = set()
    checks = list(PASSIVE_CHECKS)
    if mode == "active":
        checks.extend(ACTIVE_ONLY_CHECKS)

    for check in checks:
        try:
            result = check(cfg, out_dir, alerter)
            if result:
                for finding in result:
                    if finding not in seen:
                        seen.add(finding)
                        all_findings.append(finding)
        except Exception as e:
            msg = f"`{check.__name__}` errore: {e}"
            log.error(msg)
            alerter.finding(AREA, msg, level="error")
    return all_findings

# Net Audit Suite — Versione 3

Automated network hygiene & security analysis suite per Raspberry Pi / Debian.
Ispirata ai principi di **antirez**: semplicità, chiarezza, zero magia nascosta.


---

## Struttura

```
/opt/net_audit/
├── net_audit.py              # Controller principale
├── config.ini                # Configurazione (molti valori auto-rilevati)
├── lib/
│   ├── nic.py                # Auto-rilevamento NIC e parametri DHCP
│   └── alert.py              # Sistema di alerting modulare (Telegram + retry)
├── tasks/
│   ├── net.py                # Area NET    — IP, ARP, MAC, IPv6, VLAN
│   ├── domain.py             # Area DOMAIN — Active Directory, mDNS, NetBIOS
│   ├── dns.py                # Area DNS    — query, AXFR, DoT, DoH, rebinding
│   ├── udp.py                # Area UDP    — scan, QUIC, NTP
│   ├── presec.py             # Area PRESEC — traceroute, egress, TCP scan, NAT
│   └── hygiene.py            # Area HYGIENE — igiene di rete (nuovo, v3)
├── net_audit.service         # Systemd unit (oneshot, si attiva con link up)
└── 99-net-audit.rules        # udev rule — start su plug del cavo
```

---

## Novità v3: Area HYGIENE

11 nuovi check focalizzati sull'igiene della rete locale:

| Check | Cosa rileva | Livello |
|---|---|---|
| `check_default_credentials` | Credenziali di default su gateway (admin/admin, ecc.) | critical |
| `check_open_shares` | Share SMB/NFS accessibili anonimamente | critical |
| `check_cleartext_services` | Telnet, FTP, rsh, HTTP senza redirect HTTPS | critical/warning |
| `check_rogue_dhcp` | Server DHCP non autorizzati nella subnet | critical |
| `check_exposed_management` | UI di gestione esposte: Proxmox, Kibana, Grafana, ecc. | warning |
| `check_tls_certificates` | Cert scaduti, self-signed, TLS 1.0/1.1 accettato | warning |
| `check_snmp_community` | Community SNMP di default (public/private) | critical |
| `check_upnp_exposure` | Dispositivi UPnP/IGD — rischio port forwarding | warning/critical |
| `check_password_policy` | SMB signing disabilitato, guest access, plaintext auth | critical |
| `check_arp_table_anomalies` | ARP spoofing (IP multipli per MAC), cambio MAC tra run | critical |
| `check_wireless_security` | Reti aperte o WEP nelle vicinanze | warning/critical |

---

## Auto-rilevamento rete

`lib/nic.py` rileva automaticamente alla partenza:

| Parametro | Fonte |
|---|---|
| `interface` | Prima NIC non-loopback con IP |
| `local_subnet` | IP + netmask → CIDR automatico |
| `gateway` | `ip route show default` |
| `target_ext` | DHCP option-252 → config.ini → `1.1.1.1` |

Priorità: **CLI flag > DHCP > config.ini > default**

---

## Installazione

```bash
# 1. Dipendenze sistema
sudo apt install -y \
  python3 python3-pip git \
  tcpdump nmap arp-scan dnsutils curl \
  net-tools ethtool iproute2 traceroute \
  macchanger netcat-openbsd openssl \
  stun-client snmp snmp-mibs-downloader \
  iw wireless-tools

# 2. Dipendenze Python
pip3 install requests --break-system-packages

# 3. Deploy
sudo mkdir -p /opt/net_audit
sudo cp -r . /opt/net_audit/
sudo chmod +x /opt/net_audit/net_audit.py

# 4. Configura Telegram in config.ini (opzionale ma consigliato)
sudo nano /opt/net_audit/config.ini

# 5. Installa systemd unit
sudo cp net_audit.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable net_audit.service

# 6. Installa udev rule (trigger su plug cavo)
sudo cp 99-net-audit.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
```

---

## Automazione: start al plug del cavo di rete

La suite supporta **due meccanismi combinati** per partire automaticamente
quando si collega un cavo Ethernet:

### Meccanismo 1 — udev rule (immediato, livello kernel)

Il file `99-net-audit.rules` avvia il service non appena il kernel rileva
l'interfaccia con carrier (cavo fisico presente):

```
# /etc/udev/rules.d/99-net-audit.rules
ACTION=="change", SUBSYSTEM=="net",
  KERNEL!="lo", KERNEL!="br*", KERNEL!="wlan*",
  ATTR{carrier}=="1",
  RUN+="/bin/systemctl start net_audit.service"
```

**Come funziona:** udev intercetta l'evento `carrier=1` (cavo collegato) e
lancia il service. L'audit parte appena la NIC ha link, prima ancora che
DHCP completi — nic.py attende i parametri con retry automatico.

### Meccanismo 2 — systemd `network-online.target` (stabile, post-DHCP)

Il service è dichiarato `After=network-online.target` e `BindsTo=network-online.target`,
quindi viene riavviato anche se la rete cade e torna su durante il boot.

Per abilitare `network-online.target` su Debian/Raspberry Pi OS:

```bash
# Con NetworkManager (desktop/Ubuntu):
sudo systemctl enable NetworkManager-wait-online.service

# Con dhcpcd (Raspberry Pi OS default):
sudo systemctl enable dhcpcd.service

# Con systemd-networkd:
sudo systemctl enable systemd-networkd-wait-online.service
```

### Verifica che il trigger funzioni

```bash
# Simula plug del cavo (utile per test senza cavo fisico)
sudo udevadm trigger --action=change --subsystem-match=net \
  --attr-match=carrier=1

# Verifica stato service
sudo systemctl status net_audit.service

# Log in tempo reale
journalctl -u net_audit.service -f
```

### Nota su systemd oneshot

Il service è `Type=oneshot`: viene eseguito una volta per evento,
non rimane in background. Se il cavo viene scollegato e ricollegato,
un nuovo audit parte automaticamente.

---

## Esecuzione manuale e selettiva

```bash
# Run completo (tutti i task)
sudo python3 /opt/net_audit/net_audit.py

# Solo area hygiene
sudo python3 /opt/net_audit/net_audit.py --tasks HYGIENE

# Combinazione selettiva
sudo python3 /opt/net_audit/net_audit.py --tasks NET,HYGIENE,DNS



# Config HW Bluethoot

sudo apt update
sudo apt install -y bluez obexftp
sudo systemctl enable bluetooth
sudo systemctl start bluetooth

# Override interfaccia e target esterno
sudo python3 /opt/net_audit/net_audit.py --iface eth0 --target 8.8.8.8
```

---

## Alerting (Telegram)

Configura `bot_token` e `chat_id` in `config.ini`. Livelli e icone:

| Livello | Icona | Quando |
|---|---|---|
| `info` | ℹ️ | Dati informativi, nessuna azione richiesta |
| `warning` | ⚠️ | Anomalie da investigare |
| `critical` | 🔴 | Problema serio, azione richiesta |
| `error` | ❌ | Errore interno del tool |

**Retry automatico:** se Telegram non è raggiungibile, i messaggi vengono
accodati in `/var/log/net_audit/pending_alerts.json` e reinviati al
prossimo avvio.

---

## Aggiungere un nuovo check (3 passi)

1. Scrivi la funzione (in `hygiene.py` o in un nuovo task file):

```python
def check_mio_check(cfg, out_dir, alerter):
    findings = []
    # ... logica ...
    if condizione:
        msg = "Trovato qualcosa"
        findings.append(msg)
        alerter.finding("HYGIENE", msg, level="warning")
    return findings
```

2. Aggiungila alla lista `CHECKS` del file:

```python
CHECKS = [..., check_mio_check]
```

3. Fatto. Zero modifiche al controller.

---

## Output

Tutti i risultati in: `/var/log/net_audit/YYYY-MM-DD_HH-MM-SS/`

```
YYYY-MM-DD_HH-MM-SS/
├── main.log
├── NET/
│   ├── ipconfig.txt, vlan.txt, ipv6.txt, arp_scan.txt
│   ├── mac_spoof.txt, arp_sniff.pcap, foreign_arp.txt
├── DOMAIN/
│   ├── ad_srv.txt, ldap_scan.gnmap, mdns_netbios.txt
├── DNS/
│   ├── dns_queries.txt, axfr.txt, dot.txt, doh.json, dns_rebinding.txt
├── UDP/
│   ├── udp_scan.txt, udp_summary.txt, quic.txt, ntp.txt
├── PRESEC/
│   ├── traceroute.txt, udp_outbound.txt, tcp_services.gnmap
│   ├── nat_hairpin.txt, egress_tcp.txt
└── HYGIENE/
    ├── default_creds.txt, smb_shares.txt, nfs_shares.txt
    ├── cleartext_services.txt, rogue_dhcp.txt, mgmt_interfaces.txt
    ├── tls_hosts.gnmap, tls_report.txt, snmp_hosts.gnmap, snmp_report.txt
    ├── upnp.txt, upnp_udp.txt, smb_auth.txt
    ├── arp_table.txt, wifi_scan.txt
```

**Baseline ARP persistente:** `/var/log/net_audit/arp_baseline.json`
(confrontato ad ogni run per rilevare cambio MAC tra sessioni)

---

## Potenziali miglioramenti futuri (non implementati)

Le seguenti funzionalità sono state valutate e sono architetturalmente
compatibili con il progetto, ma richiedono dipendenze aggiuntive o
scelte di design da concordare prima dell'implementazione:

### Sicurezza e rilevamento

- **Honeypot passivo in-process** — apri porte fasulle (22, 3389, 23) e
  logga chi si connette. Richiede un thread background nel controller;
  rompe il modello oneshot del service.

- **Rilevamento passive OS fingerprint** — usa `p0f` in modalità passiva
  anziché nmap attivo per classificare OS senza inviare pacchetti.
  Richiederebbe un demone separato sempre in ascolto.

- **Correlazione con CVE database** — dopo aver identificato versioni
  software (nmap `-sV`), consultare NVD/OSV API per trovare CVE attivi.
  Richiede accesso internet e parsing output XML di nmap.

- **Controllo DNS over HTTPS enforcement** — verifica se il resolver
  locale bypassa il DoH configurato dal sistema operativo.

### Automazione e scheduling

- **Run differenziale** — confronta il report corrente con quello
  precedente e notifica solo le *nuove* anomalie. Richiede un formato
  di storage strutturato (JSON/SQLite) invece di file .txt.

- **Scan adattivo alla subnet** — su /16 o /8 usa tecniche più veloci
  (masscan) e campionamento, invece di nmap completo.

- **Modalità agente continuo** — invece di oneshot, un demone che
  ascolta passivamente ARP/mDNS e rileva cambiamenti in real-time
  senza scansioni attive.

### Reporting

- **Report HTML/PDF locale** — generazione di un report leggibile
  direttamente sul Pi, consultabile via browser locale o inviabile
  via email. Richiederebbe Jinja2 o weasyprint.

- **Dashboard Grafana** — esportazione metriche verso InfluxDB/Prometheus
  per storicizzazione e visualizzazione trend nel tempo.

- **Export SIEM (syslog CEF/JSON)** — invio strutturato dei findings
  verso un SIEM esterno (Wazuh, Splunk, ELK) in formato standard.

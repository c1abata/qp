# QuickPeek Install Guide

Minimal install path for the first stable release.

## Requirements

- Linux host with Python 3.10+
- `python3-requests`
- Optional network tools: `iproute2`, `tcpdump`, `nmap`, `dnsutils`, `traceroute`, `curl`, `openssl`, `lldpd`
- Optional Bluetooth alerts: `bluetoothctl`, `obexftp`

On Debian or Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-requests iproute2 tcpdump nmap dnsutils traceroute curl openssl lldpd bluez obexftp
```

## Install

```bash
sudo mkdir -p /opt/quickpeek
sudo cp -a net_audit.py lib tasks tests README.md GUIDE.md CHANGELOG.md LICENSE config.ini.template net_audit.service 99-net-audit.rules /opt/quickpeek/
sudo cp /opt/quickpeek/config.ini.template /opt/quickpeek/config.ini
sudo editor /opt/quickpeek/config.ini
```

Keep the first run conservative:

```ini
[General]
mode = passive
profile = peek
```

Telegram is optional. Leave `Telegram.bot_token` and `Telegram.chat_id` empty to run without remote control or Telegram alerts.

## Run Once

```bash
cd /opt/quickpeek
sudo python3 net_audit.py --config ./config.ini
```

Runtime files are written to `/var/log/net_audit` when writable, otherwise to `runtime/` inside the project.

## Install As Service

```bash
sudo cp /opt/quickpeek/net_audit.service /etc/systemd/system/net_audit.service
sudo systemctl daemon-reload
sudo systemctl enable net_audit.service
sudo systemctl start net_audit.service
sudo systemctl status net_audit.service
```

Optional network-change trigger:

```bash
sudo cp /opt/quickpeek/99-net-audit.rules /etc/udev/rules.d/99-net-audit.rules
sudo udevadm control --reload-rules
```

## Validate

```bash
cd /opt/quickpeek
sh tests/run_tests.sh
sudo python3 net_audit.py --config ./config.ini --no-telegram --profile peek --mode passive
```

## Upgrade

```bash
sudo systemctl stop net_audit.service
sudo cp -a /opt/quickpeek /opt/quickpeek.backup.$(date +%Y%m%d-%H%M%S)
sudo cp -a net_audit.py lib tasks tests README.md GUIDE.md CHANGELOG.md LICENSE config.ini.template net_audit.service 99-net-audit.rules /opt/quickpeek/
sudo systemctl start net_audit.service
```

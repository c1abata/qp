# QuickPeek

QuickPeek is a modular network audit suite focused on operational simplicity:
- one linear orchestrator (`net_audit.py`)
- modular tasks in `tasks/`
- minimal dependencies
- persistent runtime state and clear logs
- safe `peek` profile for unfamiliar networks

The design follows antirez-style principles: explicit control flow, small components, predictable behavior, easy debugging.

## Security Engineering Principles

- Fast checks first: bounded timeouts, low-impact probes.
- Low-noise by default: informational findings unless policy is explicitly violated.
- Policy-driven severity: warnings/critical only when configuration says behavior is forbidden.
- Safe defaults: aggressive checks are opt-in.
- Unknown networks use local-first observation: no subnet sweep unless `profile=audit` and `mode=active`.

## Project Layout

```text
qp/
├── net_audit.py
├── config.ini.template
├── net_audit.service
├── 99-net-audit.rules
├── lib/
│   ├── alert.py
│   ├── bluetooth_alert.py
│   ├── correlator.py
│   ├── logger.py
│   ├── nic.py
│   ├── runtime.py
│   ├── taskloader.py
│   └── tgcontrol.py
└── tasks/
    ├── net.py
    ├── domain.py
    ├── dns.py
    ├── udp.py
    ├── presec.py
    ├── hygiene.py
    ├── health.py
    ├── net_discovery.py
    ├── passive_scan.py
    ├── dhcp_rogue.py
    ├── vlan_8021x.py
    ├── lldp_map.py
    ├── mitm_detect.py
    ├── tor.py
    ├── tldcheck.py
    ├── streaming.py
    ├── dns_tunnelling.py
    └── check_network_doh_dot_policy.py
```

## Runtime Paths

QuickPeek tries to write under `/var/log/net_audit`.
If not writable, it falls back to local `qp/runtime/`.

Created paths:
- `runtime/state.json` (bot offsets, overrides, last run summary)
- `runtime/logs/audit-*.log` (run logs)
- `runtime/tasks/<timestamp>/...` (task outputs)
- `runtime/pending_alerts.json` (Telegram retry queue)

## Quick Start

1. Copy template:

```bash
cp config.ini.template config.ini
```

2. Edit `config.ini` (at least `Telegram.bot_token` and `Telegram.chat_id` if Telegram is needed).

Recommended first run:
- keep `mode=passive`
- keep `profile=peek`
- keep `Policy.*` values to `false`
- review baseline output
- then enable strict policy flags for your environment

3. Run:

```bash
python3 net_audit.py --config ./config.ini
```

Useful options:

```bash
python3 net_audit.py --mode passive
python3 net_audit.py --profile peek --mode passive
python3 net_audit.py --profile audit --mode active
python3 net_audit.py --mode active
python3 net_audit.py --tasks dns,udp,health
python3 net_audit.py --iface eth0 --subnet 192.168.1.0/24
python3 net_audit.py --no-telegram
```

Run local tests:

```bash
sh tests/run_tests.sh
```

## Policy and False Positives

`[Policy]` controls when findings become actionable warnings:

- `dns_plaintext_forbidden = true`
: warns when DNS over port 53 is reachable.
- `doh_dot_forbidden = true`
: warns when DoH/DoT is reachable.
- `enable_snmp_default_check = true`
: enables active SNMP default community checks (opt-in).

If these flags are `false`, related findings stay informational to reduce false positives.

## Safe Quick Peek

`profile=peek` is the default for unknown or unexplored networks. It favors local evidence:
- selected interface, IP, subnet, gateway
- configured DNS resolvers
- ARP/neighbor table size
- passive packet/L2 indicators when local tools allow it

It does not sweep the subnet. Broader checks belong in `profile=audit`, and active scan tasks are blocked when the detected subnet exceeds `Safety.max_scan_hosts` unless `Safety.allow_large_scan=true`.

## Telegram Bot Commands

Supported commands:
- `/help`
- `/ping`
- `/status`
- `/mode passive|active`
- `/profile peek|audit`
- `/interface eth0|auto`
- `/subnet 192.168.1.0/24|auto`
- `/tasks`
- `/tasks set net,dns,udp`
- `/scan`

Command overrides are persisted in `runtime/state.json` and applied on subsequent runs.

## Telegram Setup and Debug Checklist

1. Create a bot with BotFather and copy token.
2. Send a message to the bot from the target chat.
3. Resolve chat ID with:

```bash
curl "https://api.telegram.org/bot<TOKEN>/getUpdates"
```

4. Put `bot_token` and `chat_id` in `config.ini`.
5. Validate direct send:

```bash
curl -X POST "https://api.telegram.org/bot<TOKEN>/sendMessage" \
  -H "Content-Type: application/json" \
  -d '{"chat_id":"<CHAT_ID>","text":"quickpeek test"}'
```

If alerts are not delivered:
- check `runtime/logs/audit-*.log`
- check `runtime/pending_alerts.json`
- verify chat id matches exactly the sender/group
- ensure outbound HTTPS to `api.telegram.org` is allowed

## Stable Release Workflow

Suggested sequence:

```bash
git add .
git commit -m "quickpeek: harden checks, reduce false positives, improve runtime/bot"
git tag -a v1.0.0 -m "QuickPeek stable release v1.0.0"
git push origin main
git push origin v1.0.0
```

## Systemd / Udev (optional)

Artifacts included:
- `net_audit.service`
- `99-net-audit.rules`

These can trigger QuickPeek on network changes and system boot.

## Add a New Task

Create `tasks/my_task.py`:

```python
def run(net):
    return [{
        "type": "my_task",
        "severity": "info",
        "message": "example event",
        "source": "my_task",
    }]
```

Then add `my_task` to `Tasks.enabled` in `config.ini`.

Legacy tasks are also supported with signature:

```python
def run(cfg, out_dir, alerter, mode="passive"):
    ...
```

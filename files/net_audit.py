#!/usr/bin/env python3
"""
net_audit.py - Network Analysis Suite v3
Principi: semplicità, chiarezza, zero magia nascosta. (antirez-style)
"""

import os
import sys
import logging
import configparser
import argparse
from datetime import datetime


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.nic      import detect_network_params
from lib.alert    import Alerter
from tasks        import net, domain, dns, udp, presec, hygiene, health

def load_config(path):
    cfg = configparser.ConfigParser()
    read_ok = cfg.read(path)
    if not read_ok:
        print(f"[WARN] config.ini non trovato in '{path}', uso valori di default.", file=sys.stderr)
    # Garantisce che la sezione [General] esista sempre
    if "General" not in cfg:
        cfg["General"] = {}
    if "Telegram" not in cfg:
        cfg["Telegram"] = {}
    if "Scan" not in cfg:
        cfg["Scan"] = {}
    if "DNS" not in cfg:
        cfg["DNS"] = {}
    return cfg

def setup_logging(base_dir):
    os.makedirs(base_dir, exist_ok=True)
    logging.basicConfig(
        filename=f"{base_dir}/main.log",
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    logging.getLogger().addHandler(logging.StreamHandler(sys.stderr))

def main():
    parser = argparse.ArgumentParser(description="Net Audit Suite v3")
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    parser.add_argument("--config", default=os.path.join(_script_dir, "config.ini"))
    parser.add_argument("--iface",  help="Override interface")
    parser.add_argument("--target", help="Override target esterno")
    parser.add_argument(
        "--tasks",
        default="NET,DOMAIN,DNS,UDP,PRESEC,HYGIENE,HEALTH",
        help="Task da eseguire (comma-separated). Es: --tasks NET,HYGIENE"
    )
    args = parser.parse_args()

    cfg = load_config(args.config)

    iface = args.iface or cfg.get("General", "interface", fallback=None)
    net_params = detect_network_params(iface)

    if net_params["interface"]:
        cfg["General"]["interface"]    = net_params["interface"]
    if net_params["local_subnet"]:
        cfg["General"]["local_subnet"] = net_params["local_subnet"]
    if net_params["gateway"]:
        cfg["General"]["gateway"]      = net_params["gateway"]

    target_external = (
        args.target
        or net_params.get("dhcp_target")
        or cfg.get("General", "target_external", fallback="1.1.1.1")
    )
    cfg["General"]["target_external"] = target_external

    alerter = Alerter(cfg)

    date_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base_dir = f"/var/log/net_audit/{date_str}"
    setup_logging(base_dir)

    logging.info("=== Net Audit v3 avviato ===")
    logging.info(f"Interface : {cfg['General']['interface']}")
    logging.info(f"Subnet    : {cfg['General']['local_subnet']}")
    logging.info(f"Gateway   : {cfg['General'].get('gateway','?')}")
    logging.info(f"Target ext: {cfg['General']['target_external']}")

    alerter.send(
        f"🚀 *Net Audit v3 avviato*\n"
        f"Iface: `{cfg['General']['interface']}`\n"
        f"Subnet: `{cfg['General']['local_subnet']}`\n"
        f"Gateway: `{cfg['General'].get('gateway','?')}`\n"
        f"Target: `{cfg['General']['target_external']}`",
        level="info"
    )

    ALL_TASKS = {
        "NET":     net.run,
        "DOMAIN":  domain.run,
        "DNS":     dns.run,
        "UDP":     udp.run,
        "PRESEC":  presec.run,
        "HYGIENE": hygiene.run,
        "HEALTH": health.run,
    }

    selected = [t.strip().upper() for t in args.tasks.split(",")]
    TASKS = [(name, ALL_TASKS[name]) for name in selected if name in ALL_TASKS]

    results = {}
    for name, func in TASKS:
        task_dir = f"{base_dir}/{name}"
        os.makedirs(task_dir, exist_ok=True)
        logging.info(f"--- Inizio {name} ---")
        try:
            findings = func(cfg, task_dir, alerter)
            results[name] = findings or []
            logging.info(f"{name} completato: {len(results[name])} finding(s)")
        except Exception as exc:
            msg = f"❌ *{name}* errore critico: `{exc}`"
            logging.error(msg)
            alerter.send(msg, level="error")
            results[name] = []

    total = sum(len(v) for v in results.values())
    summary_lines = [
        f"📋 *Report finale Net Audit v3*",
        f"Subnet: `{cfg['General']['local_subnet']}`",
        f"Totale findings: *{total}*", "",
    ]
    for name, findings in results.items():
        icon = "🔴" if findings else "✅"
        summary_lines.append(f"{icon} *{name}*: {len(findings)} finding(s)")
        for f in findings[:5]:
            summary_lines.append(f"  • {f[:120]}")
        if len(findings) > 5:
            summary_lines.append(f"  … e altri {len(findings)-5}, vedi log")

    alerter.send("\n".join(summary_lines), level="info")
    logging.info(f"=== Audit completato. {total} finding(s) totali ===")

if __name__ == "__main__":
    main()

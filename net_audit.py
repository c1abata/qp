#!/usr/bin/env python3
"""QuickPeek main orchestrator.

Antirez-inspired principles applied:
- one explicit control flow
- small modules with clear responsibility
- no hidden global magic
- robust behavior under partial failures
"""

from __future__ import annotations

import argparse
import configparser
import logging
import os
import sys
from datetime import datetime, timezone


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from lib.alert import Alerter
from lib import correlator, logger as qp_logger, nic, runtime, safety, taskloader, tgcontrol


LOG = logging.getLogger("quickpeek")


def _ensure_sections(cfg: configparser.ConfigParser) -> None:
    for section in [
        "General",
        "Network",
        "Telegram",
        "Alerts",
        "Policy",
        "Tasks",
        "Scan",
        "DNS",
        "Hygiene",
        "Bluetooth",
        "Safety",
    ]:
        if section not in cfg:
            cfg[section] = {}

    defaults = {
        ("General", "mode"): "passive",
        ("General", "profile"): "peek",
        ("General", "target_external"): "1.1.1.1",
        ("General", "interface"): "auto",
        ("Network", "target_subnet"): "auto",
        ("Telegram", "enabled"): "true",
        ("Tasks", "enabled"): ",".join(taskloader.DEFAULT_TASKS),
        ("Tasks", "peek_enabled"): ",".join(taskloader.PEEK_TASKS),
        ("Alerts", "send_info"): "false",
        ("Alerts", "send_warning"): "true",
        ("Alerts", "send_critical"): "true",
        ("Policy", "dns_plaintext_forbidden"): "false",
        ("Policy", "doh_dot_forbidden"): "false",
        ("Policy", "enable_snmp_default_check"): "false",
        ("Safety", "max_scan_hosts"): "256",
        ("Safety", "allow_large_scan"): "false",
    }

    for (section, key), value in defaults.items():
        if not cfg.get(section, key, fallback="").strip():
            cfg[section][key] = value


def load_config(path: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    loaded = cfg.read(path)
    if not loaded:
        print(f"[WARN] config file not found: {path}. Using defaults.", file=sys.stderr)
    _ensure_sections(cfg)
    return cfg


def _first_target(raw_value: str) -> str:
    values = [x.strip() for x in raw_value.split(",") if x.strip()]
    return values[0] if values else "1.1.1.1"


def _severity_counts(events: list[dict]) -> dict:
    counts = {"info": 0, "warning": 0, "critical": 0, "error": 0}
    for event in events:
        sev = str(event.get("severity", "warning")).lower()
        if sev not in counts:
            sev = "warning"
        counts[sev] += 1
    counts["total_events"] = sum(counts.values())
    return counts


def _summary_text(mode: str, net: dict, summary: dict, events: list[dict]) -> str:
    lines = [
        "QuickPeek summary",
        f"mode: {mode}",
        f"iface: {net.get('iface')}",
        f"subnet: {net.get('subnet')}",
        f"events: total={summary['total_events']} info={summary['info']} warning={summary['warning']} critical={summary['critical']} error={summary['error']}",
    ]

    top = events[:10]
    if top:
        lines.append("top findings:")
        for item in top:
            sev = item.get("severity", "warning")
            src = item.get("source", "core")
            msg = str(item.get("message", "")).strip()
            lines.append(f"- [{sev}] [{src}] {msg[:180]}")

    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="QuickPeek")
    parser.add_argument("--config", default=os.path.join(SCRIPT_DIR, "config.ini"))
    parser.add_argument("--iface", help="Override interface")
    parser.add_argument("--subnet", help="Override local subnet (CIDR)")
    parser.add_argument("--target", help="Override external target")
    parser.add_argument("--mode", choices=["passive", "active"], help="Override operational mode")
    parser.add_argument("--profile", choices=["peek", "audit"], help="Task profile: safe local peek or full audit")
    parser.add_argument("--tasks", help="Comma-separated task list")
    parser.add_argument("--no-telegram", action="store_true", help="Disable Telegram control/alerts for this run")
    parser.add_argument("--quiet", action="store_true", help="Disable stderr log output")
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    cfg = load_config(args.config)

    if args.no_telegram:
        cfg["Telegram"]["bot_token"] = ""
        cfg["Telegram"]["chat_id"] = ""

    state = runtime.load_state()

    available_tasks = list(taskloader.DEFAULT_TASKS)
    tg_actions = tgcontrol.process(cfg, state, available_tasks)

    if tg_actions.get("messages"):
        for line in tg_actions["messages"]:
            print(f"[TG] {line}", file=sys.stderr)

    overrides = dict(state.get("overrides", {})) if isinstance(state.get("overrides"), dict) else {}
    if args.iface:
        overrides["interface"] = args.iface
    if args.subnet:
        overrides["subnet"] = args.subnet

    net = nic.get_network_info(cfg, overrides=overrides)

    if net.get("iface"):
        cfg["General"]["interface"] = str(net["iface"])
    if net.get("subnet"):
        cfg["General"]["local_subnet"] = str(net["subnet"])
    if net.get("gateway"):
        cfg["General"]["gateway"] = str(net["gateway"])

    target_external = args.target or net.get("dhcp_target") or cfg.get("General", "target_external", fallback="1.1.1.1")
    cfg["General"]["target_external"] = _first_target(target_external)

    mode = args.mode or overrides.get("mode") or cfg.get("General", "mode", fallback="passive")
    mode = str(mode).strip().lower()
    if mode not in {"passive", "active"}:
        mode = "passive"
    cfg["General"]["mode"] = mode

    profile = args.profile or overrides.get("profile") or cfg.get("General", "profile", fallback="peek")
    profile = str(profile).strip().lower()
    if profile not in {"peek", "audit"}:
        profile = "peek"
    cfg["General"]["profile"] = profile

    for policy_key in ["dns_plaintext_forbidden", "doh_dot_forbidden", "enable_snmp_default_check"]:
        if policy_key in overrides:
            cfg["Policy"][policy_key] = str(overrides[policy_key]).lower()

    configured_tasks = args.tasks or overrides.get("tasks")
    if not configured_tasks:
        key = "peek_enabled" if profile == "peek" else "enabled"
        configured_tasks = cfg.get("Tasks", key, fallback="")
    task_names = taskloader.parse_tasks(configured_tasks)
    peek_tasks = taskloader.parse_tasks(cfg.get("Tasks", "peek_enabled", fallback=""))
    task_names = safety.select_tasks(profile, task_names, peek_tasks)

    max_hosts = cfg.getint("Safety", "max_scan_hosts", fallback=256)
    allow_large_scan = safety.bool_value(cfg.get("Safety", "allow_large_scan", fallback="false"))

    loaded_tasks, load_errors = taskloader.load_tasks(task_names)

    p = runtime.paths()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join(p["tasks_dir"], run_id)
    os.makedirs(run_dir, exist_ok=True)

    log_file = os.path.join(p["logs_dir"], f"audit-{run_id}.log")
    qp_logger.configure(log_file=log_file, verbose=not args.quiet)

    alerter = Alerter(cfg)

    LOG.info("QuickPeek started")
    LOG.info("profile=%s mode=%s iface=%s subnet=%s gateway=%s target=%s", profile, mode, net.get("iface"), net.get("subnet"), net.get("gateway"), cfg["General"].get("target_external"))
    LOG.info("tasks=%s", ",".join(task_names))

    events: list[dict] = []

    for err in load_errors:
        LOG.warning(err)
        events.append({
            "type": "task_load_error",
            "severity": "warning",
            "message": err,
            "source": "taskloader",
        })

    for task_name, module in loaded_tasks:
        block_reason = safety.blocked_task_reason(task_name, mode, net.get("subnet"), max_hosts, allow_large_scan)
        if block_reason:
            LOG.warning("%s: %s", task_name, block_reason)
            events.append({
                "type": "safety_guard",
                "severity": "warning",
                "message": f"{task_name}: {block_reason}",
                "source": "safety",
            })
            continue

        task_out = os.path.join(run_dir, task_name.upper())
        os.makedirs(task_out, exist_ok=True)

        LOG.info("task start %s", task_name)
        ctx = {
            "cfg": cfg,
            "out_dir": task_out,
            "alerter": alerter,
            "mode": mode,
            "net": net,
            "state": state,
            "profile": profile,
        }

        try:
            raw = taskloader.execute_task(module, task_name, ctx)
            normalized = taskloader.normalize_result(task_name, raw)
            events.extend(normalized)
            LOG.info("task end %s findings=%d", task_name, len(normalized))
        except Exception as exc:
            LOG.exception("task error %s: %s", task_name, exc)
            events.append({
                "type": "task_error",
                "severity": "warning",
                "message": f"{task_name} failed: {exc}",
                "source": task_name,
            })

    correlated = correlator.process(events)
    summary = _severity_counts(correlated)

    for event in correlated:
        LOG.info("event type=%s severity=%s source=%s message=%s", event.get("type"), event.get("severity"), event.get("source"), event.get("message"))

    alerter.dispatch_events(correlated)
    summary_text = _summary_text(mode=f"{profile}/{mode}", net=net, summary=summary, events=correlated)
    alerter.send(summary_text, level="info")

    runtime.save_last_run(state=state, network=net, mode=f"{profile}/{mode}", summary=summary, events=correlated)

    LOG.info("QuickPeek completed total_events=%s", summary["total_events"])
    print(summary_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""
tasks/dns.py - DNS Area
Checks: query A/AAAA/MX/NS/SOA/TXT, AXFR attempt, DoT, DoH, DNS rebinding.
"""

import re
import subprocess
import logging

log = logging.getLogger(__name__)
AREA = "DNS"


def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return ""
    except Exception as e:
        log.error(f"_run {cmd[0]}: {e}")
        return ""


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_standard_queries(cfg, out_dir, alerter):
    """Query DNS standard verso resolver esterno."""
    findings = []
    resolver  = cfg["General"]["target_external"]
    test_host = cfg.get("DNS", "test_hostname", fallback="example.com")
    qtypes    = ["A", "AAAA", "MX", "NS", "SOA", "TXT"]

    results = {}
    with open(f"{out_dir}/dns_queries.txt", "w") as f:
        for qt in qtypes:
            out = _run(["dig", f"@{resolver}", test_host, qt, "+short", "+time=5"])
            f.write(f"=== {qt} ===\n{out}\n")
            results[qt] = out.strip()

    # Se A non risponde, è un problema
    if not results.get("A"):
        msg = f"Nessuna risposta DNS A da {resolver} per {test_host}"
        findings.append(msg)
        alerter.finding(AREA, msg, level="warning")

    return findings


def check_axfr(cfg, out_dir, alerter):
    """Tenta AXFR (zone transfer) - normalmente bloccato, ma vale la pena provare."""
    findings = []
    resolver  = cfg["General"]["target_external"]
    try:
        resolv = open("/etc/resolv.conf").read()
        m = re.search(r'search\s+(\S+)', resolv)
        domain = m.group(1) if m else "example.com"
    except Exception:
        domain = "example.com"

    out = _run(["dig", f"@{resolver}", domain, "AXFR", "+time=5"])
    with open(f"{out_dir}/axfr.txt", "w") as f:
        f.write(out)

    if "Transfer failed" not in out and len(out.split("\n")) > 5 and "ANSWER" in out:
        msg = f"⚠️ AXFR riuscito su {resolver} per {domain}! Zone transfer aperta."
        findings.append(msg)
        alerter.finding(AREA, msg, level="critical")

    return findings


def check_dot(cfg, out_dir, alerter):
    """DNS over TLS (porta 853)."""
    findings = []
    # Tentiamo con openssl s_client per non richiedere kdig
    out = _run(
        ["openssl", "s_client", "-connect", "1.1.1.1:853", "-servername",
         "cloudflare-dns.com", "-verify_quiet"],
        timeout=10
    )
    with open(f"{out_dir}/dot.txt", "w") as f:
        f.write(out)

    if "Verify return code: 0" in out:
        msg = "DNS over TLS (DoT) raggiungibile su 1.1.1.1:853"
        findings.append(msg)
        alerter.finding(AREA, msg, level="info")
    else:
        msg = "DoT bloccato o non raggiungibile"
        findings.append(msg)
        alerter.finding(AREA, msg, level="warning")

    return findings


def check_doh(cfg, out_dir, alerter):
    """DNS over HTTPS."""
    findings = []
    out = _run(
        ["curl", "-sf", "-H", "accept: application/dns-json",
         "https://1.1.1.1/dns-query?name=example.com&type=A"],
        timeout=10
    )
    with open(f"{out_dir}/doh.json", "w") as f:
        f.write(out)

    if '"Status":0' in out or '"Status": 0' in out:
        msg = "DNS over HTTPS (DoH) funzionante"
        findings.append(msg)
        alerter.finding(AREA, msg, level="info")
    else:
        msg = "DoH non raggiungibile o bloccato"
        findings.append(msg)
        alerter.finding(AREA, msg, level="warning")

    return findings


def check_dns_rebinding(cfg, out_dir, alerter):
    """
    Verifica se il resolver locale risolve nomi con IP privati
    (potenziale DNS rebinding).
    """
    findings = []
    # Alcuni resolver pubblici bloccano risposte con IP RFC1918
    test_domains = [
        "localtest.me",      # risolve sempre a 127.0.0.1
        "10.0.0.1.nip.io",   # risolve a 10.0.0.1
    ]
    with open(f"{out_dir}/dns_rebinding.txt", "w") as f:
        for d in test_domains:
            out = _run(["dig", d, "A", "+short", "+time=5"])
            f.write(f"{d}: {out.strip()}\n")
            private = re.findall(r'(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|127\.\d+\.\d+\.\d+)', out)
            if private:
                msg = f"DNS rebinding possibile: {d} → {private}"
                findings.append(msg)
                alerter.finding(AREA, msg, level="warning")

    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

PASSIVE_CHECKS = [
    check_standard_queries,
    check_dot,
    check_doh,
    check_dns_rebinding,
]

ACTIVE_ONLY_CHECKS = [
    check_axfr,
]

def run(cfg, out_dir, alerter, mode="active"):
    all_findings = []
    checks = list(PASSIVE_CHECKS)
    if mode == "active":
        checks.extend(ACTIVE_ONLY_CHECKS)

    for check in checks:
        try:
            result = check(cfg, out_dir, alerter)
            if result:
                all_findings.extend(result)
        except Exception as e:
            msg = f"`{check.__name__}` errore: {e}"
            log.error(msg)
            alerter.finding(AREA, msg, level="error")
    return all_findings

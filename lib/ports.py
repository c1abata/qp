"""Small helpers for operator-configurable port lists."""

from __future__ import annotations


def parse_port_spec(raw: str | None, fallback: str = "") -> list[int]:
    """Parse comma-separated ports and ranges into a sorted unique list."""
    value = (raw or fallback or "").strip()
    ports: set[int] = set()

    for item in value.split(","):
        token = item.strip()
        if not token:
            continue
        if "-" in token:
            start_raw, end_raw = token.split("-", 1)
            try:
                start = int(start_raw.strip())
                end = int(end_raw.strip())
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            for port in range(start, end + 1):
                if 1 <= port <= 65535:
                    ports.add(port)
            continue

        try:
            port = int(token)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            ports.add(port)

    return sorted(ports)


def nmap_port_arg(raw: str | None, fallback: str = "") -> str:
    """Normalize a port spec for nmap -p while preserving compact ranges."""
    ports = parse_port_spec(raw, fallback=fallback)
    if not ports:
        return ""

    ranges: list[str] = []
    start = prev = ports[0]
    for port in ports[1:]:
        if port == prev + 1:
            prev = port
            continue
        ranges.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = port
    ranges.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(ranges)

#!/usr/bin/env python3
from lib import safety


def test_peek_profile_filters_to_allowed_tasks():
    selected = safety.select_tasks(
        "peek",
        ["quickpeek", "net_discovery", "tor", "net"],
        ["quickpeek", "net"],
    )
    assert selected == ["quickpeek", "net"]


def test_active_scan_blocks_large_private_subnet():
    reason = safety.blocked_task_reason(
        "net_discovery",
        "active",
        "10.0.0.0/16",
        max_hosts=256,
        allow_large_scan=False,
    )
    assert "blocked" in reason
    assert "65536" in reason


def test_passive_mode_does_not_block_passive_task():
    reason = safety.blocked_task_reason(
        "quickpeek",
        "passive",
        "10.0.0.0/16",
        max_hosts=256,
        allow_large_scan=False,
    )
    assert reason == ""


def test_public_subnet_blocks_active_scan():
    reason = safety.blocked_task_reason(
        "net_discovery",
        "active",
        "8.8.8.0/24",
        max_hosts=256,
        allow_large_scan=True,
    )
    assert "not private" in reason


if __name__ == "__main__":
    test_peek_profile_filters_to_allowed_tasks()
    test_active_scan_blocks_large_private_subnet()
    test_passive_mode_does_not_block_passive_task()
    test_public_subnet_blocks_active_scan()

#!/usr/bin/env python3
from lib.ports import nmap_port_arg, parse_port_spec


def test_parse_port_spec_deduplicates_and_sorts():
    assert parse_port_spec("8189,5678,100-102,102,0,70000,bad") == [100, 101, 102, 5678, 8189]


def test_nmap_port_arg_compacts_ranges():
    assert nmap_port_arg("22,23,24,80,443,8189") == "22-24,80,443,8189"


if __name__ == "__main__":
    test_parse_port_spec_deduplicates_and_sorts()
    test_nmap_port_arg_compacts_ranges()

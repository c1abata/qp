#!/usr/bin/env sh
set -eu

python3 -m py_compile net_audit.py lib/*.py tasks/*.py tests/*.py
PYTHONPATH=. python3 tests/test_safety.py

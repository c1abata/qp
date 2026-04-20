#!/usr/bin/env python3
"""Central logging setup for QuickPeek."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path


DEFAULT_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def configure(log_file: str, verbose: bool = True) -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    # Idempotent setup.
    for handler in list(root.handlers):
        root.removeHandler(handler)

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter(DEFAULT_FORMAT))
    root.addHandler(file_handler)

    if verbose:
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(logging.Formatter(DEFAULT_FORMAT))
        root.addHandler(stream_handler)


def get(name: str) -> logging.Logger:
    return logging.getLogger(name)

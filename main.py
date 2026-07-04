#!/usr/bin/env python3
"""CyberGuard CLI entry script.

This is a thin shim that simply forwards into :func:`cyberguard.cli.main`.
Running ``python main.py --help`` should produce the same help text as
``python -m cyberguard --help``.
"""

from __future__ import annotations

import sys

from cyberguard.cli import main

if __name__ == "__main__":
    sys.exit(main())

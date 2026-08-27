#!/usr/bin/env python3
"""Run: .venv/bin/python contrib/audit-agent/run.py --repo owner/name --dry-run"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow `python contrib/audit-agent/run.py` without PYTHONPATH
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from audit_agent.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())

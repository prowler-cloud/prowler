"""Make contrib/audit-agent importable for tests without changing root pyproject.toml."""

from __future__ import annotations

import sys
from pathlib import Path

_AUDIT_AGENT_ROOT = Path(__file__).resolve().parents[2] / "contrib" / "audit-agent"
if str(_AUDIT_AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(_AUDIT_AGENT_ROOT))

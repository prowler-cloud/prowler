"""Shared HTTP helpers for Audit Agent API calls."""

from __future__ import annotations

import ssl


def ssl_context() -> ssl.SSLContext:
    """Prefer certifi CA bundle when available."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()

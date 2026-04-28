"""Standalone helper for tool-wrapper provider detection.

A provider is a "tool wrapper" if it delegates scanning to an external tool
(Trivy, promptfoo, etc.) instead of running checks/services through the
standard Prowler engine. This module is the single source of truth for that
classification across the codebase.

Kept as a leaf module with no Prowler imports beyond the leaf
`external_tool_providers` so it can be referenced from `prowler.lib.check.*`
and `prowler.providers.common.provider` without forming an import cycle.
"""

import importlib.metadata

from prowler.lib.check.external_tool_providers import EXTERNAL_TOOL_PROVIDERS

# Module-level cache for entry-point classes consulted by this helper.
# Independent of `Provider._ep_providers` to keep this module leaf — the cost
# of a duplicate cache entry is negligible (one class object per external
# provider, loaded lazily on first lookup).
_ep_class_cache: dict = {}


def _load_ep_class(provider: str):
    """Return the entry-point provider class for `provider`, or None.

    Caches the result in `_ep_class_cache`. Errors during entry-point loading
    are swallowed (returning None) so a broken plug-in never crashes the
    is-tool-wrapper check; it just falls through to "not a tool wrapper".
    """
    if provider in _ep_class_cache:
        return _ep_class_cache[provider]
    for ep in importlib.metadata.entry_points(group="prowler.providers"):
        if ep.name == provider:
            try:
                cls = ep.load()
            except Exception:
                cls = None
            _ep_class_cache[provider] = cls
            return cls
    _ep_class_cache[provider] = None
    return None


def is_tool_wrapper_provider(provider: str) -> bool:
    """Return True if the provider delegates scanning to an external tool.

    Combines the built-in `EXTERNAL_TOOL_PROVIDERS` frozenset (fast path for
    iac/llm/image) with the `is_external_tool_provider` class attribute of
    external plug-ins registered via entry points. This is the single source
    of truth consulted by `__main__`, the `CheckMetadata` validators, the
    check-loading utilities, and the checks loader.
    """
    if provider in EXTERNAL_TOOL_PROVIDERS:
        return True
    cls = _load_ep_class(provider)
    return bool(cls and getattr(cls, "is_external_tool_provider", False))

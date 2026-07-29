"""Leaf helper for built-in provider detection.

Lives in its own module — with no imports back into `prowler.lib.check` — so
that callers in `prowler.lib.check.*` can ask "is this provider built-in?"
without creating an import cycle through `prowler.providers.common.provider`
(which transitively imports `prowler.config.config` and from there
`prowler.lib.check.compliance_models` / `prowler.lib.check.external_tool_providers`).

Same rationale as `prowler.lib.check.tool_wrapper`: extracting the predicate
to a leaf module is the canonical way to break the cycle in this codebase.
"""

import importlib.util


def is_builtin_provider(provider: str) -> bool:
    """Return True if the provider's own package ships with the SDK.

    Wraps `importlib.util.find_spec` in `try/except (ImportError, ValueError)`
    because `find_spec` propagates `ModuleNotFoundError` when a parent package
    in the dotted path does not exist (instead of returning `None`). The
    try/except is what makes the call safe for external providers, whose
    package does not live under `prowler.providers.{provider}`.
    """
    try:
        spec = importlib.util.find_spec(f"prowler.providers.{provider}")
        return spec is not None
    except (ImportError, ValueError):
        return False

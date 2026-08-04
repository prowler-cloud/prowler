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


def builtin_check_module(provider: str, service: str, check_name: str) -> str:
    """Return the module path a built-in check would live at."""
    return f"prowler.providers.{provider}.services.{service}.{check_name}.{check_name}"


def is_builtin_check(provider: str, service: str, check_name: str) -> bool:
    """Return True if the check's module ships with the SDK.

    Sibling of `is_builtin_provider`, and unsafe for the same reason if probed
    naively: `find_spec` imports the parent package in order to search it, so
    asking about a check that lives in a plug-in raises `ModuleNotFoundError`
    rather than returning `None`. A check registered through
    `prowler.checks.{provider}` never has a parent under
    `prowler.providers.{provider}.services.{service}`, so the naive probe makes
    every external check on a built-in provider unresolvable.

    Unlike its sibling this one narrows the exception instead of swallowing
    every `ImportError`. A provider either ships with the SDK or it does not,
    but callers rely on this probe to tell "the check is not built-in" apart
    from "the check is built-in and its imports are broken". Reporting the
    second as the first would turn a broken dependency into a silent
    "check not found".
    """
    module = builtin_check_module(provider, service, check_name)
    try:
        return importlib.util.find_spec(module) is not None
    except ModuleNotFoundError as error:
        # Only absorb "this check is simply not here". `error.name` is the
        # module that could not be imported; when it is the check's own path
        # (or a prefix of it) the check does not ship with the SDK. Anything
        # else — a missing third-party dependency, say — belongs to a built-in
        # check that does exist and must stay loud.
        if error.name is None or (
            error.name != module and not module.startswith(f"{error.name}.")
        ):
            raise
        return False
    except ValueError:
        return False

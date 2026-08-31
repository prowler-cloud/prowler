"""Whether the domain-wide policy values describe what every user actually gets."""

from typing import FrozenSet, List, Optional


def _listing(settings: List[str]) -> str:
    return f"{', '.join(settings)} {'are' if len(settings) > 1 else 'is'}"


def unevaluable_reason(policies, evaluated_settings: FrozenSet[str]) -> Optional[str]:
    """Return why the domain-wide values cannot be judged at all, or None.

    In both cases the values a check would read were never reported, so every
    condition it evaluates would be built on Prowler's own defaults.
    """
    if policies.unresolved_scope:
        return (
            "the root organizational unit could not be resolved, so the "
            "domain-wide policies could not be told apart from the ones scoped "
            "to an organizational unit"
        )
    unobserved = sorted(set(policies.unobserved_settings) & evaluated_settings)
    if unobserved:
        return (
            f"{_listing(unobserved)} only configured for a group or an "
            f"organizational unit, so no domain-wide value was reported"
        )
    return None


def failures_shadowed_by_overrides(policies, failing_settings: FrozenSet[str]) -> bool:
    """Whether every failing setting is also overridden below the domain."""
    return bool(failing_settings) and failing_settings <= set(
        policies.overridden_settings
    )


def override_caveat(policies, evaluated_settings: FrozenSet[str]) -> str:
    """Return what a group or an OU also overrides on top of the domain, or an empty string."""
    overridden = sorted(set(policies.overridden_settings) & evaluated_settings)
    if not overridden:
        return ""
    return (
        f"{_listing(overridden)} also overridden for at least one group or "
        f"organizational unit, so this does not describe every user"
    )

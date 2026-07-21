"""Shared evaluation of a requirement's configuration constraints.

Some compliance requirements only hold if the configurable checks they map to
ran with a configuration strict enough for the requirement. For example CIS AWS
6.0 requirement 2.11 ("credentials unused for 45 days or more are disabled")
maps `iam_user_accesskey_unused` (config `max_unused_access_keys_days`); if the
user loosens that to 120 days the check can PASS while the requirement is, in
fact, not satisfied.

A requirement declares its expectations via ``ConfigRequirements`` (a list of
``{Check, ConfigKey, Operator, Value}``). The configuration a scan applied is a
single, scan-global mapping (the provider's ``audit_config``), so the rules are
evaluated against that mapping directly. This module is consumed by the SDK
compliance outputs (CSV + CLI table) and by the Prowler App backend so the rule
lives in one place.
"""

from typing import Any, Optional

# Leading sentence of the message prepended to a finding's ``status_extended``
# when its requirement's config constraints are not satisfied and the status is
# forced to FAIL. It opens every config-not-valid message, so it doubles as a
# stable marker for detecting the case programmatically.
CONFIG_NOT_VALID_PREFIX = "Configuration not valid for this requirement."


def _format_value(value: Any) -> str:
    """Render a constraint value for a user-facing message (lists comma-joined)."""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item) for item in value)
    return str(value)


def _describe_violation(
    check: Any, config_key: Any, applied: Any, operator: str, expected: Any
) -> str:
    """Return a product-friendly explanation of why a config violates a constraint.

    The message names the check and config key, the value the scan applied, what
    the requirement needs, and how to fix it, in plain language rather than the
    operator/value pair.

    Args:
        check: the check the requirement maps to (e.g. ``iam_user_accesskey_unused``).
        config_key: the config option that was too loose (e.g. ``max_unused_access_keys_days``).
        applied: the value the scan actually applied.
        operator: the constraint operator (``lte``/``gte``/``eq``/``in``/``subset``/``superset``).
        expected: the value the requirement expects.

    Returns:
        A full, human-readable message ending with an actionable fix.
    """
    applied_str = _format_value(applied)
    expected_str = _format_value(expected)
    needs, fix = {
        "lte": (
            f"a value of {expected_str} or lower",
            f"Update it to {expected_str} or lower.",
        ),
        "gte": (
            f"a value of {expected_str} or higher",
            f"Update it to {expected_str} or higher.",
        ),
        "eq": (
            f"it set to {expected_str}",
            f"Update it to {expected_str}.",
        ),
        "in": (
            f"it set to one of {expected_str}",
            f"Update it to one of {expected_str}.",
        ),
        "subset": (
            f"it limited to {expected_str}",
            f"Remove any value that is not in {expected_str}.",
        ),
        "superset": (
            f"it to include {expected_str}",
            f"Make sure it includes {expected_str}.",
        ),
    }.get(operator, (f"a different value (expected {operator} {expected_str})", ""))
    message = (
        f"{CONFIG_NOT_VALID_PREFIX} The check {check} has {config_key} set to "
        f"{applied_str}, but the requirement needs {needs}."
    )
    return f"{message} {fix}".strip()


def _check_operator(applied: Any, operator: str, expected: Any) -> bool:
    """Return whether ``applied`` satisfies ``operator`` against ``expected``."""
    try:
        if operator == "lte":
            return applied <= expected
        if operator == "gte":
            return applied >= expected
        if operator == "eq":
            return applied == expected
        if operator == "in":
            return applied in expected
        if operator in ("subset", "superset"):
            # Set comparisons for list-valued configs (allowlists / denylists).
            # Both sides must be collections; anything else is not satisfiable.
            if not isinstance(applied, (list, tuple, set)) or not isinstance(
                expected, (list, tuple, set)
            ):
                return False
            applied_set, expected_set = set(applied), set(expected)
            if operator == "subset":
                return applied_set <= expected_set
            return applied_set >= expected_set
    except TypeError:
        # Mismatched/unhashable types → treat as not satisfied.
        return False
    # Unknown operator: do not block the requirement on a malformed constraint.
    return True


def evaluate_config_constraints(
    config_requirements: Optional[list[Any]],
    audit_config: Optional[dict[str, Any]],
    provider_type: Optional[str] = None,
) -> tuple[bool, str]:
    """Evaluate a requirement's config constraints against the scan's config.

    Args:
        config_requirements: list of constraints, each a mapping (or object with
            the same attributes) holding ``Check``, ``ConfigKey``, ``Operator``,
            ``Value`` and an optional ``Provider``. ``None``/empty means the
            requirement has no config expectations.
        audit_config: the scan-global configuration mapping (the provider's
            ``audit_config``, i.e. ``{config_key: value}``). The applied config
            is identical across every resource and region of a scan.
        provider_type: the provider being scanned (e.g. ``aws``). A constraint
            tagged with a ``Provider`` is only evaluated when it matches this
            value; this scopes universal (multi-provider) framework constraints
            to the right provider. ``None`` disables provider scoping (every
            constraint is evaluated), which is the correct behaviour for
            single-provider frameworks.

    Returns:
        ``(is_compliant, reason)``. ``is_compliant`` is ``True`` when there are
        no constraints or every explicitly-set value satisfies its constraint.
        When a configured value violates a constraint, returns ``(False, reason)``
        describing the first violation. A constraint whose ``ConfigKey`` was not
        explicitly set is skipped (the check's default is assumed to match what
        the requirement expects).
    """
    if not config_requirements:
        return True, ""

    audit_config = audit_config or {}

    for constraint in config_requirements:
        # Accept both dicts (API template) and objects (Pydantic model).
        if isinstance(constraint, dict):
            check = constraint.get("Check")
            config_key = constraint.get("ConfigKey")
            operator = constraint.get("Operator")
            expected = constraint.get("Value")
            provider = constraint.get("Provider")
        else:
            check = getattr(constraint, "Check", None)
            config_key = getattr(constraint, "ConfigKey", None)
            operator = getattr(constraint, "Operator", None)
            expected = getattr(constraint, "Value", None)
            provider = getattr(constraint, "Provider", None)

        # Constraint scoped to another provider → not applicable to this scan.
        # Compared case-insensitively (and trimmed) so a constraint authored as
        # e.g. "AWS" still scopes to the "aws" scan instead of being silently
        # bypassed by a casing/format mismatch.
        if (
            provider
            and provider_type
            and str(provider).strip().lower() != str(provider_type).strip().lower()
        ):
            continue

        if config_key not in audit_config:
            # Config not explicitly set → default is assumed adequate.
            continue

        applied = audit_config[config_key]
        if not _check_operator(applied, operator, expected):
            reason = _describe_violation(check, config_key, applied, operator, expected)
            return False, reason

    return True, ""


def get_scan_audit_config() -> dict[str, Any]:
    """Return the scan-global applied configuration (the provider's audit_config).

    The applied config is identical across every resource and region of a scan,
    so every compliance output evaluates constraints against this single mapping.
    Imported lazily to avoid a circular import with the provider package and to
    keep this module usable from contexts without a global provider.

    Returns:
        The provider's ``audit_config`` mapping, or ``{}`` when no global
        provider is set (``AttributeError``) or the provider package cannot be
        imported (``ImportError``).
    """
    try:
        from prowler.providers.common.provider import Provider

        return Provider.get_global_provider().audit_config or {}
    except (AttributeError, ImportError):
        # No global provider set, or provider package unavailable.
        return {}


def get_scan_provider_type() -> str:
    """Return the provider being scanned (e.g. ``aws``) for constraint scoping.

    Imported lazily to avoid a circular import with the provider package and to
    keep this module usable from contexts without a global provider.

    Returns:
        The provider's ``type`` (e.g. ``aws``), or ``""`` when no global provider
        is set (``AttributeError``) or the provider package cannot be imported
        (``ImportError``); an empty string disables provider scoping.
    """
    try:
        from prowler.providers.common.provider import Provider

        return Provider.get_global_provider().type or ""
    except (AttributeError, ImportError):
        # No global provider set, or provider package unavailable.
        return ""


def _requirement_id(requirement: Any) -> Optional[str]:
    """Return a requirement's id across the legacy (``Id``) and universal (``id``) models."""
    return getattr(requirement, "Id", None) or getattr(requirement, "id", None)


def _requirement_constraints(requirement: Any) -> Optional[list]:
    """Return a requirement's config constraints across both model flavours.

    Legacy ``Compliance_Requirement`` exposes ``ConfigRequirements`` (a list of
    Pydantic models); ``UniversalComplianceRequirement`` exposes
    ``config_requirements`` (a list of dicts). ``evaluate_config_constraints``
    handles both element types.
    """
    return getattr(requirement, "ConfigRequirements", None) or getattr(
        requirement, "config_requirements", None
    )


def build_requirement_config_status(
    requirements: list[Any],
    audit_config: Optional[dict[str, Any]] = None,
    provider_type: Optional[str] = None,
) -> dict[str, tuple[bool, str]]:
    """Map every requirement id to its ``(is_compliant, reason)`` config verdict.

    Only requirements that actually declare constraints are included; callers use
    ``dict.get(req_id)`` (returning ``None`` → no constraints → no override).

    Args:
        requirements: the framework's requirements (legacy or universal models).
        audit_config: the applied config; resolved via ``get_scan_audit_config``
            when omitted.
        provider_type: the provider being scanned, for constraint scoping;
            resolved via ``get_scan_provider_type`` when omitted.

    Returns:
        A mapping ``{requirement_id: (is_compliant, reason)}`` containing only the
        requirements that declare config constraints.
    """
    if audit_config is None:
        audit_config = get_scan_audit_config()
    if provider_type is None:
        provider_type = get_scan_provider_type()
    status = {}
    for requirement in requirements:
        constraints = _requirement_constraints(requirement)
        if constraints:
            status[_requirement_id(requirement)] = evaluate_config_constraints(
                constraints, audit_config, provider_type
            )
    return status


def resolve_requirement_config_status(
    requirement: Any,
    audit_config: dict[str, Any],
    cache: dict,
    provider_type: Optional[str] = None,
) -> tuple[bool, str]:
    """Return a requirement's ``(is_compliant, reason)`` verdict, memoised in ``cache``.

    For table generators that iterate findings × compliances and only encounter
    each requirement lazily.

    Args:
        requirement: the requirement (legacy or universal model).
        audit_config: the scan-global applied config.
        cache: a dict keyed by requirement id, reused across the whole table
            build to memoise verdicts.
        provider_type: the provider being scanned, for constraint scoping;
            resolved via ``get_scan_provider_type`` when omitted.

    Returns:
        The ``(is_compliant, reason)`` verdict; ``(True, "")`` when the
        requirement declares no constraints.
    """
    req_id = _requirement_id(requirement)
    if req_id not in cache:
        constraints = _requirement_constraints(requirement)
        if constraints:
            if provider_type is None:
                provider_type = get_scan_provider_type()
            cache[req_id] = evaluate_config_constraints(
                constraints, audit_config, provider_type
            )
        else:
            cache[req_id] = (True, "")
    return cache[req_id]


def apply_config_status(
    status: str,
    status_extended: str,
    config_status: Optional[tuple[bool, str]],
) -> tuple[str, str]:
    """Override a finding's ``(status, status_extended)`` when its config is invalid.

    A requirement whose configurable checks ran with a config too loose to trust
    is forced to ``FAIL`` regardless of the finding's own status, with the reason
    prepended to ``status_extended``.

    Args:
        status: the finding's original status (e.g. ``PASS`` / ``FAIL``).
        status_extended: the finding's extended status message.
        config_status: the ``(is_compliant, reason)`` tuple from
            ``build_requirement_config_status``/``resolve_requirement_config_status``,
            or ``None`` when the requirement declares no constraints.

    Returns:
        The ``(status, status_extended)`` to report: unchanged when the config is
        valid (or ``config_status`` is ``None``); otherwise ``FAIL`` with the
        reason prepended to ``status_extended``.
    """
    if not config_status or config_status[0]:
        return status, status_extended
    return (
        "FAIL",
        f"{config_status[1]} {status_extended}".strip(),
    )


def get_effective_status(
    status: str,
    config_status: Optional[tuple[bool, str]],
) -> str:
    """Return the effective status for table aggregation.

    Args:
        status: the finding's original status.
        config_status: the ``(is_compliant, reason)`` tuple, or ``None`` when the
            requirement declares no constraints.

    Returns:
        ``FAIL`` when ``config_status`` marks the config invalid; otherwise the
        finding's original ``status``.
    """
    if not config_status or config_status[0]:
        return status
    return "FAIL"


def accumulate_overview_status(
    index: int,
    status: str,
    pass_indices: set,
    fail_indices: set,
    muted_indices: set,
) -> None:
    """Record a finding in the overview totals once, with FAIL precedence over PASS (sets mutated in place)."""
    if status == "Muted":
        muted_indices.add(index)
    elif status == "FAIL":
        fail_indices.add(index)
        pass_indices.discard(index)
    elif status == "PASS" and index not in fail_indices:
        pass_indices.add(index)


def accumulate_group_status(
    index: int,
    status: str,
    counts: dict,
    seen: dict,
) -> None:
    """Count a finding once per group, upgrading a counted PASS to FAIL on conflict (mutates ``counts``/``seen``)."""
    previous = seen.get(index)
    if status == "MANUAL":
        # MANUAL findings come from manual, checks-less requirements and are
        # informational only: they have no PASS/FAIL/Muted column in the section
        # tally, so counting them would raise KeyError on counts[status] += 1.
        # Skip them (an unexpected status still raises loudly below).
        return
    if previous is None:
        seen[index] = status
        counts[status] += 1
    elif previous == "PASS" and status == "FAIL":
        seen[index] = "FAIL"
        counts["PASS"] -= 1
        counts["FAIL"] += 1

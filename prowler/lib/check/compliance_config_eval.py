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

# Prefix prepended to a finding's ``status_extended`` when its requirement's
# config constraints are not satisfied and the status is forced to FAIL.
CONFIG_NOT_VALID_PREFIX = "[CONFIG NOT VALID]"


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
    config_requirements: Optional[list],
    audit_config: Optional[dict],
) -> tuple[bool, str]:
    """Evaluate a requirement's config constraints against the scan's config.

    Args:
        config_requirements: list of constraints, each a mapping (or object with
            the same attributes) holding ``Check``, ``ConfigKey``, ``Operator``
            and ``Value``. ``None``/empty means the requirement has no config
            expectations.
        audit_config: the scan-global configuration mapping (the provider's
            ``audit_config``, i.e. ``{config_key: value}``). The applied config
            is identical across every resource and region of a scan.

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
        else:
            check = getattr(constraint, "Check", None)
            config_key = getattr(constraint, "ConfigKey", None)
            operator = getattr(constraint, "Operator", None)
            expected = getattr(constraint, "Value", None)

        if config_key not in audit_config:
            # Config not explicitly set → default is assumed adequate.
            continue

        applied = audit_config[config_key]
        if not _check_operator(applied, operator, expected):
            reason = (
                f"config not valid for requirement: {check}.{config_key}="
                f"{applied!r} does not satisfy {operator} {expected!r}"
            )
            return False, reason

    return True, ""


def get_scan_audit_config() -> dict:
    """Return the scan-global applied configuration (the provider's audit_config).

    The applied config is identical across every resource and region of a scan,
    so every compliance output evaluates constraints against this single mapping.
    Imported lazily to avoid a circular import with the provider package and to
    keep this module usable from contexts without a global provider (returns
    ``{}`` if no provider is set or audit_config is unavailable).
    """
    try:
        from prowler.providers.common.provider import Provider

        return Provider.get_global_provider().audit_config or {}
    except Exception:
        return {}


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
    requirements: list,
    audit_config: Optional[dict] = None,
) -> dict:
    """Map every requirement id to its ``(is_compliant, reason)`` config verdict.

    Only requirements that actually declare constraints are included; callers use
    ``dict.get(req_id)`` (returning ``None`` → no constraints → no override).

    Args:
        requirements: the framework's requirements (legacy or universal models).
        audit_config: the applied config; resolved via ``get_scan_audit_config``
            when omitted.
    """
    if audit_config is None:
        audit_config = get_scan_audit_config()
    status = {}
    for requirement in requirements:
        constraints = _requirement_constraints(requirement)
        if constraints:
            status[_requirement_id(requirement)] = evaluate_config_constraints(
                constraints, audit_config
            )
    return status


def resolve_requirement_config_status(
    requirement: Any,
    audit_config: dict,
    cache: dict,
) -> tuple[bool, str]:
    """Return a requirement's ``(is_compliant, reason)`` verdict, memoised in ``cache``.

    For table generators that iterate findings × compliances and only encounter
    each requirement lazily. ``cache`` is keyed by requirement id and reused
    across the whole table build.
    """
    req_id = _requirement_id(requirement)
    if req_id not in cache:
        constraints = _requirement_constraints(requirement)
        cache[req_id] = (
            evaluate_config_constraints(constraints, audit_config)
            if constraints
            else (True, "")
        )
    return cache[req_id]


def apply_config_status(
    status: str,
    status_extended: str,
    config_status: Optional[tuple],
) -> tuple[str, str]:
    """Override a finding's ``(status, status_extended)`` when its config is invalid.

    A requirement whose configurable checks ran with a config too loose to trust
    is forced to ``FAIL`` regardless of the finding's own status, with the reason
    prepended to ``status_extended``. ``config_status`` is the ``(ok, reason)``
    tuple from ``build_requirement_config_status`` (``None`` → no constraints).
    """
    if not config_status or config_status[0]:
        return status, status_extended
    return (
        "FAIL",
        f"{CONFIG_NOT_VALID_PREFIX} {config_status[1]}. {status_extended}",
    )


def get_effective_status(
    status: str,
    config_status: Optional[tuple],
) -> str:
    """Return the effective status for table aggregation (``FAIL`` if config invalid)."""
    if not config_status or config_status[0]:
        return status
    return "FAIL"

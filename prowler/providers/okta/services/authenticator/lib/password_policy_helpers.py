from prowler.lib.check.models import CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_service import (
    PasswordPolicy,
)

_SCOPE_ADVICE = (
    "Grant it on the Okta API Scopes tab of the service app in the Okta Admin "
    "Console, then re-run the check."
)


def active_password_policies(
    password_policies: dict[str, PasswordPolicy],
) -> list[PasswordPolicy]:
    """Return active password policies sorted by priority.

    Treats `policy.status == ""` as ACTIVE: the typed Okta SDK
    occasionally returns policies without a `status` field populated
    (the SDK enum doesn't cover every server-side value Okta has
    shipped). Dropping those would silently hide real policies — we
    'd rather evaluate them and let the per-field comparator decide.
    """
    return sorted(
        [
            policy
            for policy in password_policies.values()
            if not policy.status or policy.status.upper() == "ACTIVE"
        ],
        key=lambda policy: (
            policy.priority if policy.priority is not None else float("inf"),
            policy.name,
        ),
    )


def password_policy_label(policy: PasswordPolicy) -> str:
    kind = "default" if policy.is_default else "custom"
    priority = policy.priority if policy.priority is not None else "unset"
    return f"Password Policy {policy.name} (priority {priority}, {kind})"


def no_active_password_policies_finding(
    metadata, org_domain: str, requirement: str
) -> CheckReportOkta:
    """Build the FAIL finding emitted when no active password policies exist."""
    placeholder = PasswordPolicy(
        id="password-policies-missing",
        name="(no active password policies)",
        status="MISSING",
    )
    report = CheckReportOkta(
        metadata=metadata, resource=placeholder, org_domain=org_domain
    )
    report.status = "FAIL"
    report.status_extended = (
        "No active Okta Password Policies were returned by the API. "
        f"The organization must enforce: {requirement}."
    )
    return report


def missing_password_policies_scope_finding(
    metadata, org_domain: str, scope: str, requirement: str
) -> CheckReportOkta:
    """Build the MANUAL finding emitted when Password Policies cannot be listed."""
    placeholder = PasswordPolicy(
        id="password-policies-scope-missing",
        name="(scope not granted)",
        status="UNKNOWN",
    )
    report = CheckReportOkta(
        metadata=metadata, resource=placeholder, org_domain=org_domain
    )
    report.status = "MANUAL"
    report.status_extended = (
        f"Could not retrieve Okta Password Policies to evaluate {requirement}: "
        f"the Okta service app is missing the required `{scope}` API scope. "
        f"{_SCOPE_ADVICE}"
    )
    return report

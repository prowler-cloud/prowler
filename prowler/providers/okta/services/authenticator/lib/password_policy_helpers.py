from collections.abc import Callable

from prowler.lib.check.models import CheckReportOkta
from prowler.providers.okta.lib.service.scope import missing_scope_finding
from prowler.providers.okta.services.authenticator.authenticator_service import (
    POLICIES_READ_SCOPE,
    PasswordPolicy,
)


def active_password_policies(
    password_policies: dict[str, PasswordPolicy],
) -> list[PasswordPolicy]:
    """Return active password policies sorted by priority."""
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
    return f"Password Policy '{policy.name}' (priority {priority}, {kind})"


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


def execute_password_policy_check(
    *,
    metadata,
    org_domain: str,
    password_policies: dict[str, PasswordPolicy],
    missing_scopes: list[str],
    field_name: str,
    requirement: str,
    compliant: Callable[[object], bool],
    actual_label: str,
) -> list[CheckReportOkta]:
    """Evaluate a scalar password-policy setting across all active policies."""
    if POLICIES_READ_SCOPE in missing_scopes:
        return [
            missing_scope_finding(
                metadata=metadata,
                org_domain=org_domain,
                resource_id="okta-password-policies",
                resource_name="Okta Password Policies",
                missing_scopes=[POLICIES_READ_SCOPE],
                action="evaluate active Password Policy settings",
            )
        ]

    policies = active_password_policies(password_policies)
    if not policies:
        return [no_active_password_policies_finding(metadata, org_domain, requirement)]

    findings: list[CheckReportOkta] = []
    for policy in policies:
        actual = getattr(policy, field_name)
        report = CheckReportOkta(
            metadata=metadata, resource=policy, org_domain=org_domain
        )
        if compliant(actual):
            report.status = "PASS"
            report.status_extended = (
                f"{password_policy_label(policy)} enforces {requirement} "
                f"({actual_label}: {actual})."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                f"{password_policy_label(policy)} does not enforce {requirement} "
                f"({actual_label}: {actual})."
            )
        findings.append(report)
    return findings

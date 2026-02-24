from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    GrantControlOperator,
    RiskLevel,
)


class entra_conditional_access_policy_require_password_change_high_risk_users(Check):
    """Check if a Conditional Access policy requires password change and MFA for high-risk users.

    This check verifies that at least one enabled Conditional Access policy enforces
    both password change and MFA (with AND operator) for users flagged with high user
    risk level, covering all users and all cloud applications.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check for password change requirement on high-risk users.

        Iterates through all Conditional Access policies to find one that:
        - Is enabled (not disabled or report-only)
        - Applies to all users and all cloud applications
        - Includes 'high' in user risk levels
        - Requires both 'mfa' and 'passwordChange' with AND operator

        Returns:
            list[CheckReportM365]: A list containing the check result.
        """
        findings = []

        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = "No Conditional Access Policy requires password change and MFA for high-risk users."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if "All" not in policy.conditions.user_conditions.included_users:
                continue

            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            if (
                ConditionalAccessGrantControl.PASSWORD_CHANGE
                not in policy.grant_controls.built_in_controls
                or ConditionalAccessGrantControl.MFA
                not in policy.grant_controls.built_in_controls
                or policy.grant_controls.operator != GrantControlOperator.AND
            ):
                continue

            if not policy.conditions.user_risk_levels:
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )

            if RiskLevel.HIGH not in policy.conditions.user_risk_levels:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' requires password change and MFA for user risk but does not include 'high' risk level."
            elif (
                policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING
            ):
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' requires password change and MFA for high-risk users but is set to report-only mode and does not enforce it."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' requires password change and MFA for high-risk users."
                break

        findings.append(report)

        return findings

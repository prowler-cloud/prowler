from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client
from prowler.providers.microsoft365.services.entra.entra_service import (
    AdminRoles,
    AuthenticationStrength,
    ConditionalAccessPolicyState,
)


class entra_ca_policy_admin_users_phishing_resistant_mfa_enabled(Check):
    """Check if Conditional Access policies require Phishing-resistant MFA strength for admin users."""

    def execute(self) -> list[CheckReportMicrosoft365]:
        """Execute the check to ensure that Conditional Access policies require Phishing-resistant MFA strength for admin users.

        Returns:
            list[CheckReportMicrosoft365]: A list containing the results of the check.
        """
        findings = []
        report = CheckReportMicrosoft365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = "No Conditional Access Policy requires Phishing-resistant MFA strength for admin users."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if not (
                {role.value for role in AdminRoles}.issuperset(
                    policy.conditions.user_conditions.included_roles
                )
            ):
                continue

            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
                or policy.conditions.application_conditions.excluded_applications != []
            ):
                continue

            if (
                policy.grant_controls.authentication_strength is not None
                and policy.grant_controls.authentication_strength
                == AuthenticationStrength.PHISHING_RESISTANT_MFA
            ):
                report = CheckReportMicrosoft365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.display_name,
                    resource_id=policy.id,
                )
                if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                    report.status = "FAIL"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports Phishing-resistant MFA strength for admin users but does not require it."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' requires Phishing-resistant MFA strength for admin users."
                    break

        findings.append(report)
        return findings

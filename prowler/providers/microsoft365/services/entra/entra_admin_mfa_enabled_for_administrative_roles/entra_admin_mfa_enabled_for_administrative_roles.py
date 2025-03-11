from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client
from prowler.providers.microsoft365.services.entra.entra_service import (
    AdminRoles,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
)


class entra_admin_mfa_enabled_for_administrative_roles(Check):
    """
    Ensure multifactor authentication is enabled for all users in administrative roles.

    This check verifies that at least one Conditional Access Policy in Microsoft Entra, which is in an enabled state,
    applies to administrative roles and enforces multifactor authentication (MFA). Enforcing MFA for privileged accounts
    is critical to reduce the risk of unauthorized access through compromised credentials.

    The check fails if no enabled policy is found that requires MFA for any administrative role.
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """
        Execute the admin MFA requirement check for administrative roles.

        Iterates over the Conditional Access Policies retrieved from the Entra client and generates a report
        indicating whether MFA is enforced for users in administrative roles.

        Returns:
            List[CheckReportMicrosoft365]: A list containing a single report with the result of the check.
        """
        findings = []

        report = CheckReportMicrosoft365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )

        report.status = "FAIL"
        report.status_extended = "No Conditional Access Policy requiring MFA for administrative roles was found."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state not in {
                ConditionalAccessPolicyState.ENABLED,
                ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
            }:
                continue

            if not ({admin_role.value for admin_role in AdminRoles}).issubset(
                set(policy.conditions.user_conditions.included_roles)
            ):
                if "All" not in policy.conditions.user_conditions.included_users:
                    continue

            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            if (
                ConditionalAccessGrantControl.MFA
                in policy.grant_controls.built_in_controls
            ):
                report = CheckReportMicrosoft365(
                    metadata=self.metadata(),
                    resource=entra_client.conditional_access_policies,
                    resource_name=policy.display_name,
                    resource_id=policy.id,
                )
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' requires MFA for administrative roles."
                break

        findings.append(report)
        return findings

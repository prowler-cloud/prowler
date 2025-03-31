from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client
from prowler.providers.microsoft365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
)


class entra_users_have_mfa_enabled(Check):
    """
    Ensure multifactor authentication is enabled for all users.

    This check verifies that at least one Conditional Access Policy in Microsoft Entra, which is in an enabled state,
    requires multifactor authentication for all users.

    The check fails if no enabled policy is found that requires MFA for all users.
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """
        Execute the admin MFA requirement check for all users.

        Iterates over the Conditional Access Policies retrieved from the Entra client and generates a report
        indicating whether MFA is enforced for users in all users.

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
        report.status_extended = (
            "No Conditional Access Policy enforces MFA for all users."
        )

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
                ConditionalAccessGrantControl.MFA
                in policy.grant_controls.built_in_controls
            ):
                report = CheckReportMicrosoft365(
                    metadata=self.metadata(),
                    resource=entra_client.conditional_access_policies,
                    resource_name=policy.display_name,
                    resource_id=policy.id,
                )
                if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                    report.status = "FAIL"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports MFA requirement for all users but does not enforce it."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' enforces MFA for all users."
                    break

        findings.append(report)
        return findings

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    InsiderRiskLevel,
)

OFFICE365_APP_ID = "Office365"


class entra_conditional_access_policy_block_o365_elevated_insider_risk(Check):
    """Check if a Conditional Access policy blocks Office 365 access for elevated insider risk users.

    This check verifies that at least one enabled Conditional Access policy blocks
    access to Office 365 applications for users with elevated insider risk levels,
    as determined by Microsoft Purview Adaptive Protection.

    - PASS: At least one enabled policy blocks Office 365 access for users with elevated insider risk.
    - FAIL: No enabled policy blocks Office 365 access based on insider risk signals.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check for insider risk blocking in Conditional Access policies.

        Returns:
            list[CheckReportM365]: A list containing the result of the check.
        """
        findings = []
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = "No Conditional Access Policy blocks Office 365 access for users with elevated insider risk."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if "All" not in policy.conditions.user_conditions.included_users:
                continue

            if (
                OFFICE365_APP_ID
                not in policy.conditions.application_conditions.included_applications
                and "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            if (
                ConditionalAccessGrantControl.BLOCK
                not in policy.grant_controls.built_in_controls
            ):
                continue

            # Policy targets all users, O365/All apps, and blocks access.
            # Now check if Adaptive Protection is providing insider risk signals.
            if policy.conditions.insider_risk_levels is None:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.display_name,
                    resource_id=policy.id,
                )
                report.status = "FAIL"
                if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                    report.status_extended = f"Conditional Access Policy {policy.display_name} is configured in report-only mode to block Office 365 and Microsoft Purview Adaptive Protection is not providing insider risk signals."
                else:
                    report.status_extended = f"Conditional Access Policy {policy.display_name} is configured to block Office 365 and Microsoft Purview Adaptive Protection is not providing insider risk signals."
                continue

            if policy.conditions.insider_risk_levels != InsiderRiskLevel.ELEVATED:
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )
            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy {policy.display_name} reports blocking Office 365 for elevated insider risk users but does not enforce it."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy {policy.display_name} blocks Office 365 access for users with elevated insider risk."
                break

        findings.append(report)
        return findings

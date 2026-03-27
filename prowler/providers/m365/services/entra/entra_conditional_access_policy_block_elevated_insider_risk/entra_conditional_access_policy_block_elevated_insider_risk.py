from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    InsiderRiskLevel,
)


class entra_conditional_access_policy_block_elevated_insider_risk(Check):
    """Check if a Conditional Access policy blocks all cloud app access for elevated insider risk users.

    This check verifies that at least one enabled Conditional Access policy
    blocks access to all cloud applications for users with an elevated insider
    risk level, as determined by Microsoft Purview Insider Risk Management
    and Adaptive Protection.

    - PASS: An enabled CA policy blocks all cloud app access for elevated insider risk users.
    - FAIL: No enabled CA policy blocks broad cloud app access based on insider risk signals.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = "No Conditional Access Policy blocks access for users with elevated insider risk."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if not policy.conditions.application_conditions:
                continue

            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            if InsiderRiskLevel.ELEVATED not in policy.conditions.insider_risk_levels:
                continue

            if (
                ConditionalAccessGrantControl.BLOCK
                not in policy.grant_controls.built_in_controls
            ):
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )

            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' blocks elevated insider risk users for all cloud apps but is only in report-only mode."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' blocks access to all cloud apps for users with elevated insider risk."
                break

        findings.append(report)
        return findings

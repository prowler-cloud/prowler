from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
)

# Windows Azure Service Management API application ID
AZURE_MANAGEMENT_API_APP_ID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"


class entra_require_mfa_for_management_api(Check):
    """Check if at least one enabled Conditional Access policy requires MFA for Azure Management API.

    This check verifies that at least one enabled Conditional Access policy
    requires multifactor authentication (MFA) for the Windows Azure Service
    Management API (appId: 797f4846-ba00-4fd7-ba43-dac1f8f63013), which covers
    Azure Portal, Azure CLI, Azure PowerShell, and IaC tools.

    - PASS: At least one enabled CA policy requires MFA for Azure Management API.
    - FAIL: No enabled CA policy enforces MFA for Azure Management API access.
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
        report.status_extended = (
            "No Conditional Access Policy requires MFA for Azure Management API."
        )

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if not policy.conditions.application_conditions:
                continue

            if (
                AZURE_MANAGEMENT_API_APP_ID
                not in policy.conditions.application_conditions.included_applications
                and "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            if "All" not in policy.conditions.user_conditions.included_users:
                continue

            if (
                ConditionalAccessGrantControl.MFA
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
                report.status_extended = f"Conditional Access Policy {policy.display_name} targets Azure Management API with MFA but is only in report-only mode."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy {policy.display_name} requires MFA for Azure Management API."
                break

        findings.append(report)
        return findings

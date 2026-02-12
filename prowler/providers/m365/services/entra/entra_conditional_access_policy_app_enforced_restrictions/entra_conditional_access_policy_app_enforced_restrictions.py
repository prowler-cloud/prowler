from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ClientAppType,
    ConditionalAccessPolicyState,
)


class entra_conditional_access_policy_app_enforced_restrictions(Check):
    """Check if at least one Conditional Access policy enforces application restrictions.

    This check verifies that the tenant has at least one enabled Conditional Access policy
    with application enforced restrictions to protect SharePoint, OneDrive, and Exchange
    from unmanaged devices.

    - PASS: At least one policy is enabled with application enforced restrictions targeting
            all users, all client app types, and Office365 applications.
    - FAIL: No policy meets the criteria for application enforced restrictions.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check for application enforced restrictions in Conditional Access policies.

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
        report.status_extended = "No Conditional Access Policy enforces application restrictions for unmanaged devices."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if "All" not in policy.conditions.user_conditions.included_users:
                continue

            if ClientAppType.ALL not in policy.conditions.client_app_types:
                continue

            if (
                "Office365"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            if not policy.session_controls.application_enforced_restrictions.is_enabled:
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )
            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports application enforced restrictions but does not enforce them."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' enforces application restrictions for unmanaged devices."
                break

        findings.append(report)
        return findings

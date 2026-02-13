from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    DevicePlatform,
)


class entra_policy_unknown_unsupported_device_platforms_blocked(Check):
    """Check if at least one Conditional Access policy blocks unknown or unsupported device platforms.

    This check verifies that the tenant has at least one enabled Conditional Access
    policy configured to block access from unknown or unsupported device platforms.

    - PASS: At least one enabled policy blocks all device platforms.
    - FAIL: No policy is configured to block unknown or unsupported device platforms.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check for Conditional Access policy blocking unknown device platforms.

        Returns:
            list[CheckReportM365]: A list containing the results of the check.
        """
        findings = []
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = "No Conditional Access Policy blocks unknown or unsupported device platforms."

        for policy in entra_client.conditional_access_policies.values():
            # Skip disabled policies
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            # Check if policy has block control
            if (
                ConditionalAccessGrantControl.BLOCK
                not in policy.grant_controls.built_in_controls
            ):
                continue

            # Check if policy targets all platforms
            if (
                policy.conditions.platform_conditions is None
                or DevicePlatform.ALL
                not in policy.conditions.platform_conditions.included_platforms
            ):
                continue

            # Policy meets all criteria
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )

            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports unknown device platforms but does not block them."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' blocks unknown or unsupported device platforms."
                break

        findings.append(report)
        return findings

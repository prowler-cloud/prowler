from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    DevicePlatform,
)


class entra_policy_blocks_unknown_unsupported_device_platforms(Check):
    """Check if at least one Conditional Access policy blocks unknown or unsupported device platforms.

    This check evaluates whether the tenant has a Conditional Access policy that
    blocks access for unknown or unsupported device platforms by requiring all
    platforms to be included and blocking access.
    - PASS: At least one enabled policy blocks access for all platforms (covering unknown/unsupported).
    - FAIL: No enabled policy blocks unknown or unsupported device platforms.
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
        report.status_extended = "No Conditional Access Policy blocks unknown or unsupported device platforms."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if not policy.conditions.platform_conditions:
                continue

            if (
                DevicePlatform.ALL
                not in policy.conditions.platform_conditions.included_platforms
            ):
                continue

            if (
                ConditionalAccessGrantControl.BLOCK
                in policy.grant_controls.built_in_controls
            ):
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.display_name,
                    resource_id=policy.id,
                )
                if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                    report.status = "FAIL"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports blocking unknown or unsupported device platforms but does not enforce it."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' blocks unknown or unsupported device platforms."
                    break

        findings.append(report)
        return findings

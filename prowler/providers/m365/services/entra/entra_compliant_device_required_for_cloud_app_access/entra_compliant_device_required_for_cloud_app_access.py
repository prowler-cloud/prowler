from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    GrantControlOperator,
)


class entra_compliant_device_required_for_cloud_app_access(Check):
    """Ensure a Conditional Access policy requires an MDM-compliant device for all cloud app access.

    This check verifies that at least one enabled Conditional Access policy enforces
    the compliant device grant control for all cloud applications.
    The requirement must be a hard requirement, not offered as an alternative to MFA.

    - PASS: An enabled policy requires a compliant device for all cloud app access.
    - FAIL: No policy mandates device compliance, or the requirement is only in report-only mode.
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
        report.status_extended = "No Conditional Access Policy requires an MDM-compliant device for all cloud app access."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            if (
                ConditionalAccessGrantControl.COMPLIANT_DEVICE
                not in policy.grant_controls.built_in_controls
            ):
                continue

            # Ensure compliant device is a hard requirement, not an OR alternative
            # with other controls like MFA
            if (
                policy.grant_controls.operator == GrantControlOperator.OR
                and len(policy.grant_controls.built_in_controls) > 1
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
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports the requirement of an MDM-compliant device for all cloud app access but does not enforce it."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' requires an MDM-compliant device for all cloud app access."
                break

        findings.append(report)

        return findings

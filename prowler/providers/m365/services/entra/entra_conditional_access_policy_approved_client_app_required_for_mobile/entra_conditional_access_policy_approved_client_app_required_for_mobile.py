from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    MOBILE_PLATFORMS,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    GrantControlOperator,
)

MOBILE_APP_GRANT_CONTROLS = {
    ConditionalAccessGrantControl.APPROVED_APPLICATION,
    ConditionalAccessGrantControl.COMPLIANT_APPLICATION,
}


class entra_conditional_access_policy_approved_client_app_required_for_mobile(Check):
    """Check if a Conditional Access policy requires approved client apps or app protection for mobile devices.

    This check ensures that at least one enabled Conditional Access policy
    targets iOS and Android platforms and requires approved client apps or
    app protection policies.
    - PASS: An enabled policy requires approved client apps or app protection for iOS/Android.
    - FAIL: No policy restricts mobile app access to approved or protected apps.
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
        report.status_extended = "No Conditional Access Policy requires approved client apps or app protection for mobile devices."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if not policy.conditions.platform_conditions:
                continue

            included = set(policy.conditions.platform_conditions.include_platforms)
            excluded = set(policy.conditions.platform_conditions.exclude_platforms)

            targets_mobile = (
                "all" in included or MOBILE_PLATFORMS.issubset(included)
            ) and not ("all" in excluded or MOBILE_PLATFORMS.intersection(excluded))
            if not targets_mobile:
                continue

            built_in_controls = set(policy.grant_controls.built_in_controls)
            if not MOBILE_APP_GRANT_CONTROLS.intersection(built_in_controls):
                continue

            if (
                policy.grant_controls.operator == GrantControlOperator.OR
                and not built_in_controls.issubset(MOBILE_APP_GRANT_CONTROLS)
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
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports the requirement of approved client apps or app protection for mobile devices but does not enforce it."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' requires approved client apps or app protection for mobile devices."
                break

        findings.append(report)

        return findings

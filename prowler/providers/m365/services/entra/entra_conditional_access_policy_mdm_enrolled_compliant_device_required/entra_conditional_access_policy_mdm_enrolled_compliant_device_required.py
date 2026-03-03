from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    GrantControlOperator,
)

REQUIRED_GRANT_CONTROL = ConditionalAccessGrantControl.COMPLIANT_DEVICE


class entra_conditional_access_policy_mdm_enrolled_compliant_device_required(Check):
    """Check that all users need a compliant (MDM-enrolled) device for all cloud apps."""

    def execute(self) -> list[CheckReportM365]:
        findings = []

        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = "No Conditional Access Policy requires a compliant device to access all cloud apps for all users."

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

            policy_grant_controls = set(policy.grant_controls.built_in_controls)
            if REQUIRED_GRANT_CONTROL not in policy_grant_controls:
                continue

            # If operator is OR and there are additional controls, compliant device is optional.
            if (
                policy.grant_controls.operator == GrantControlOperator.OR
                and len(policy_grant_controls) > 1
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
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' requires a compliant device for all users and all cloud apps but is configured in report-only mode."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' requires a compliant device to access all cloud apps for all users."
                break

        findings.append(report)
        return findings

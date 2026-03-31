from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    UserAction,
)


class entra_conditional_access_policy_device_registration_mfa_required(Check):
    """Ensure MFA is required for device registration."""

    def execute(self) -> list[CheckReportM365]:
        findings = []

        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = (
            "No Conditional Access Policy requires MFA for device registration."
        )

        reporting_policy = None

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if "All" not in policy.conditions.user_conditions.included_users:
                continue

            if (
                UserAction.REGISTER_DEVICE
                not in policy.conditions.application_conditions.included_user_actions
            ):
                continue

            if (
                ConditionalAccessGrantControl.MFA
                not in policy.grant_controls.built_in_controls
            ):
                continue

            if policy.state == ConditionalAccessPolicyState.ENABLED:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.display_name,
                    resource_id=policy.id,
                )
                report.status = "PASS"
                report.status_extended = (
                    f"Conditional Access Policy '{policy.display_name}' enforces MFA "
                    "for device registration."
                )
                break

            if (
                policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING
                and reporting_policy is None
            ):
                reporting_policy = policy

        if report.status == "FAIL" and reporting_policy:
            report.status_extended = (
                f"Conditional Access Policy '{reporting_policy.display_name}' reports "
                "MFA for device registration but does not enforce it."
            )

        findings.append(report)
        return findings

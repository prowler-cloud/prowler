from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client
from prowler.providers.microsoft365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    GrantControlOperator,
)


class entra_capolicy_managed_device_required_for_authentication(Check):
    """Check if Conditional Access policies deny access to the Microsoft 365

    This check ensures that Conditional Access policies are in place to enforce managed device requirement for authentication.
    """

    def execute(self) -> list[CheckReportMicrosoft365]:
        """Execute the check to ensure that Conditional Access policies enforce managed device requirement for authentication.

        Returns:
            list[CheckReportMicrosoft365]: A list containing the results of the check.
        """
        findings = []

        report = CheckReportMicrosoft365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = (
            "No Conditional Access Policy requires a managed device for authentication."
        )

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

            if (
                ConditionalAccessGrantControl.DOMAIN_JOINED_DEVICE
                not in policy.grant_controls.built_in_controls
                or ConditionalAccessGrantControl.MFA
                not in policy.grant_controls.built_in_controls
            ):
                continue

            if policy.grant_controls.operator == GrantControlOperator.OR:
                report = CheckReportMicrosoft365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.display_name,
                    resource_id=policy.id,
                )
                if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                    report.status = "FAIL"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports the requirement of a managed device for authentication but does not enforce it."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' does require a managed device for authentication."
                    break

        findings.append(report)

        return findings

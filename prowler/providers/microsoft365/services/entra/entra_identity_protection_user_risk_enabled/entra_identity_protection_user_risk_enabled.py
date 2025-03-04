from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client
from prowler.providers.microsoft365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    GrantControlOperator,
)


class entra_identity_protection_user_risk_enabled(Check):
    """Check if at least one Conditional Access policy is a Identity Protection user risk policy.

    This check ensures that at least one Conditional Access policy is a Identity Protection user risk policy.
    """

    def execute(self) -> list[CheckReportMicrosoft365]:
        """Execute the check to ensure that at least one Conditional Access policy is a Identity Protection user risk policy.

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
        report.status_extended = "No Conditional Access Policy is a user risk based Identity Protection Policy."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state not in {
                ConditionalAccessPolicyState.ENABLED,
                ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
            }:
                continue

            if "All" not in policy.conditions.user_conditions.included_users:
                continue

            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            if (
                ConditionalAccessGrantControl.PASSWORD_CHANGE
                not in policy.grant_controls.built_in_controls
                or ConditionalAccessGrantControl.MFA
                not in policy.grant_controls.built_in_controls
            ):
                continue

            if policy.grant_controls.operator == GrantControlOperator.AND:
                report = CheckReportMicrosoft365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.display_name,
                    resource_id=policy.id,
                )
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' is a user risk based Identity Protection Policy."
                break

        findings.append(report)

        return findings

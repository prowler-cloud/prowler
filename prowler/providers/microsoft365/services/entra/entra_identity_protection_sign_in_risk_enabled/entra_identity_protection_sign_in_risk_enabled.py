from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client
from prowler.providers.microsoft365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    RiskLevel,
    SignInFrequencyInterval,
)


class entra_identity_protection_sign_in_risk_enabled(Check):
    """Check if at least one Conditional Access policy is a Identity Protection sign-in risk policy.

    This check ensures that at least one Conditional Access policy is a Identity Protection sign-in risk policy.
    """

    def execute(self) -> list[CheckReportMicrosoft365]:
        """Execute the check to ensure that at least one Conditional Access policy is a Identity Protection sign-in risk policy.

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
        report.status_extended = "No Conditional Access Policy is a sign-in risk based Identity Protection Policy."

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
                ConditionalAccessGrantControl.MFA
                not in policy.grant_controls.built_in_controls
            ):
                continue

            if (
                SignInFrequencyInterval.EVERY_TIME
                != policy.session_controls.sign_in_frequency.interval
            ):
                continue

            report = CheckReportMicrosoft365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )
            if (
                RiskLevel.HIGH not in policy.conditions.sign_in_risk_levels
                or RiskLevel.MEDIUM not in policy.conditions.sign_in_risk_levels
            ):
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' is a sign-in risk based Identity Protection Policy but does not protect against high and medium sign-in risk attempts."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' is a sign-in risk based Identity Protection Policy and does protect against high and medium risk potential sign-in attempts."
                break

        findings.append(report)

        return findings

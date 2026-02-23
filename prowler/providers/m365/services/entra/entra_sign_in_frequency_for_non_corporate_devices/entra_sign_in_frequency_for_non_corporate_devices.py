from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessPolicyState,
    SignInFrequencyInterval,
)


class entra_sign_in_frequency_for_non_corporate_devices(Check):
    """Check if at least one Conditional Access Policy enforces sign-in frequency for non-corporate devices."""

    def execute(self) -> list[CheckReportM365]:
        """Execute the check for sign-in frequency enforcement on non-corporate devices.

        Returns:
            list[CheckReportM365]: A list containing the check result.
        """
        findings = []
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."

        for policy in entra_client.conditional_access_policies.values():
            if (
                policy.state == ConditionalAccessPolicyState.DISABLED
                or "All"
                not in policy.conditions.user_conditions.included_users
                or "All"
                not in policy.conditions.application_conditions.included_applications
                or not policy.session_controls.sign_in_frequency.is_enabled
                or policy.session_controls.sign_in_frequency.interval
                != SignInFrequencyInterval.TIME_BASED
            ):
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )

            if (
                policy.state
                == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING
            ):
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports sign-in frequency for non-corporate devices but does not enforce it."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' enforces sign-in frequency for non-corporate devices."
                break

        findings.append(report)
        return findings

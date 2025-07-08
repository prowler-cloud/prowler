from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessPolicyState,
    SignInFrequencyInterval,
)


class entra_intune_enrollment_sign_in_frequency_every_time(Check):
    """Ensure sign-in frequency for Intune Enrollment is set to 'Every time'."""

    def execute(self) -> list[CheckReportM365]:
        """Execute the check to ensure that sign-in frequency for Intune Enrollment is set to 'Every time'.

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
        report.status_extended = "No Conditional Access Policy enforces Every Time sign-in frequency for Intune Enrollment."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if (
                "d4ebce55-015a-49b5-a083-c84d1797ae8c"
                not in policy.conditions.application_conditions.included_applications
                and "d4ebce55-015a-49b5-a083-c84d1797ae8c"
                in policy.conditions.application_conditions.excluded_applications
            ):
                continue

            if "All" not in policy.conditions.user_conditions.included_users:
                continue

            if not policy.session_controls.sign_in_frequency.is_enabled:
                continue

            if (
                policy.session_controls.sign_in_frequency.interval
                == SignInFrequencyInterval.EVERY_TIME
            ):
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.display_name,
                    resource_id=policy.id,
                )
                if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                    report.status = "FAIL"
                    report.status_extended = f"Conditional Access Policy {policy.display_name} reports Every Time sign-in frequency for Intune Enrollment but does not enforce it."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Conditional Access Policy {policy.display_name} enforces Every Time sign-in frequency for Intune Enrollment."
                    break

        findings.append(report)
        return findings

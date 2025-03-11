from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client
from prowler.providers.microsoft365.services.entra.entra_service import (
    AdminRoles,
    ConditionalAccessPolicyState,
    SignInFrequencyInterval,
    SignInFrequencyType,
)


class entra_admin_users_sign_in_frequency_enabled(Check):
    """Check if Conditional Access policies enforce sign-in frequency for admin users.

    This check ensures that administrators have a sign-in frequency policy enabled
    and that persistent browser session settings are correctly configured.
    """

    def execute(self) -> list[CheckReportMicrosoft365]:
        """Execute the check to validate sign-in frequency enforcement for admin users.

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
            "No Conditional Access Policy enforces sign-in frequency for admin users."
        )

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if not {role.value for role in AdminRoles}.issuperset(
                policy.conditions.user_conditions.included_roles
            ):
                continue

            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            if (
                policy.session_controls.sign_in_frequency.is_enabled
                and policy.session_controls.persistent_browser.is_enabled
                and policy.session_controls.persistent_browser.mode == "never"
            ):
                recommended_sign_in_frequency = entra_client.audit_config.get(
                    "sign_in_frequency", 4
                )
                report = CheckReportMicrosoft365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.display_name,
                    resource_id=policy.id,
                )
                if (
                    policy.session_controls.sign_in_frequency.interval
                    == SignInFrequencyInterval.EVERY_TIME
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Conditional Access Policy {policy.display_name} enforces sign-in frequency for admin users but it is set to 'Every Time'."
                else:
                    frequency_in_hours = (
                        policy.session_controls.sign_in_frequency.frequency
                        if policy.session_controls.sign_in_frequency.type
                        == SignInFrequencyType.HOURS
                        else policy.session_controls.sign_in_frequency.frequency * 24
                    )
                    if frequency_in_hours > recommended_sign_in_frequency:
                        report.status = "FAIL"
                        report.status_extended = f"Conditional Access Policy '{policy.display_name}' enforces sign-in frequency to be {frequency_in_hours} hours for admin users, which is greater than the recommended {recommended_sign_in_frequency} hours."
                    else:
                        report.status = "PASS"
                        report.status_extended = f"Conditional Access Policy '{policy.display_name}' enforces sign-in frequency to be {frequency_in_hours} hours for admin users."

                    if (
                        policy.state
                        == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING
                    ):
                        report.status = "FAIL"
                        report.status_extended += " Finding status remains FAIL because the policy is still set to 'Report-only' instead of 'On'."
                break

        findings.append(report)

        return findings

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client
from prowler.providers.microsoft365.services.entra.entra_service import (
    AdminRoles,
    ConditionalAccessPolicyState,
    SignInFrequencyInterval,
    SignInFrequencyType,
)


class entra_capolicy_admin_users_sign_in_frequency_enabled(Check):
    """Check if Conditional Access policies enforce sign-in frequency for admin users."""

    def execute(self) -> list[CheckReportMicrosoft365]:
        """Validate sign-in frequency enforcement for admin users."""
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
        recommended_frequency = entra_client.audit_config.get("sign_in_frequency", 4)

        for policy in entra_client.conditional_access_policies.values():
            if (
                policy.state == ConditionalAccessPolicyState.DISABLED
                or not {role.value for role in AdminRoles}.issuperset(
                    policy.conditions.user_conditions.included_roles
                )
                or "All"
                not in policy.conditions.application_conditions.included_applications
                or not policy.session_controls.sign_in_frequency.is_enabled
                or not policy.session_controls.persistent_browser.is_enabled
                or policy.session_controls.persistent_browser.mode != "never"
            ):
                continue

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
                if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                    report.status = "FAIL"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' only reports when sign-in frequency is 'Every Time' for admin users but does not enforce it."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' enforces sign-in frequency 'Every Time' for admin users."
                    break
            elif (
                policy.session_controls.sign_in_frequency.interval
                == SignInFrequencyInterval.TIME_BASED
            ):
                frequency_hours = (
                    policy.session_controls.sign_in_frequency.frequency
                    if policy.session_controls.sign_in_frequency.type
                    == SignInFrequencyType.HOURS
                    else policy.session_controls.sign_in_frequency.frequency * 24
                )
                if frequency_hours > recommended_frequency:
                    report.status = "FAIL"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' enforces sign-in frequency at {frequency_hours} hours for admin users, exceeding the recommended {recommended_frequency} hours."
                else:
                    if (
                        policy.state
                        == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"Conditional Access Policy '{policy.display_name}' only reports when sign-in frequency is {frequency_hours} hours for admin users but does not enforce it."
                    else:
                        report.status = "PASS"
                        report.status_extended = f"Conditional Access Policy '{policy.display_name}' enforces sign-in frequency at {frequency_hours} hours for admin users."
                        break

        findings.append(report)
        return findings

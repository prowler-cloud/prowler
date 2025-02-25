from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client
from prowler.providers.microsoft365.services.entra.entra_service import (
    AdminRoles,
    ConditionalAccessPolicyState,
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
            resource=entra_client.conditional_access_policies,
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = (
            "No Conditional Access policy enforces sign-in frequency for admin users."
        )

        for policy in entra_client.conditional_access_policies.values():
            if policy.state not in {
                ConditionalAccessPolicyState.ENABLED,
                ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
            }:
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
                and policy.session_controls.sign_in_frequency.frequency
                and policy.session_controls.sign_in_frequency.frequency <= 4
                and policy.session_controls.persistent_browser.is_enabled
                and policy.session_controls.persistent_browser.mode == "never"
            ):
                report = CheckReportMicrosoft365(
                    metadata=self.metadata(),
                    resource=entra_client.conditional_access_policies,
                    resource_name=policy.display_name,
                    resource_id=policy.id,
                )
                report.status = "PASS"
                report.status_extended = f"Conditional Access policy {policy.display_name} enforces sign-in frequency for admin users."
                break

        findings.append(report)

        return findings

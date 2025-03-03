from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client
from prowler.providers.microsoft365.services.entra.entra_service import (
    AdminRoles,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
)


class entra_admin_center_role_limited_access(Check):
    """Check if Conditional Access policies deny access to the Microsoft 365 admin center for users with limited access roles.

    This check ensures that Conditional Access policies are in place to deny access to the Microsoft 365 admin center for users with limited access roles.
    """

    def execute(self) -> list[CheckReportMicrosoft365]:
        """Execute the check to ensure that Conditional Access policies deny access to the Microsoft 365 admin center for users with limited access roles.

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
        report.status_extended = "No Conditional Access policy limits Entra Admin Center access to administrative roles."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state not in {
                ConditionalAccessPolicyState.ENABLED,
                ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
            }:
                continue

            if not (
                {
                    role for role in policy.conditions.user_conditions.excluded_roles
                }.issubset({admin_role.value for admin_role in AdminRoles})
                and "All" in policy.conditions.user_conditions.included_users
            ):
                continue

            if (
                "Microsoft365AdminPortals"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            if (
                ConditionalAccessGrantControl.BLOCK
                in policy.grant_controls.built_in_controls
            ):
                report = CheckReportMicrosoft365(
                    metadata=self.metadata(),
                    resource=entra_client.conditional_access_policies,
                    resource_name=policy.display_name,
                    resource_id=policy.id,
                )
                report.status = "PASS"
                report.status_extended = f"Conditional Access policy '{policy.display_name}' limits Entra Admin Center access to administrative roles."
                break

        findings.append(report)

        return findings

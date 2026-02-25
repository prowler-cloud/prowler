from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ClientAppType,
    ConditionalAccessPolicyState,
)


class entra_app_enforced_restrictions(Check):
    """Check if at least one Conditional Access policy enforces application restrictions.

    This check verifies that the tenant has at least one enabled Conditional Access policy
    with application enforced restrictions to protect SharePoint, OneDrive, and Exchange
    from unmanaged devices.

    - PASS: At least one policy is enabled with application enforced restrictions targeting
            all users, all client app types, and either the Office365 suite or
            SharePoint Online and Exchange Online individually.
    - FAIL: No policy meets the criteria for application enforced restrictions.
    """

    # SharePoint Online / OneDrive for Business
    SHAREPOINT_APP_ID = "00000003-0000-0ff1-ce00-000000000000"
    # Exchange Online
    EXCHANGE_APP_ID = "00000002-0000-0ff1-ce00-000000000000"
    # Office 365 suite (includes SharePoint, OneDrive, and Exchange)
    OFFICE365_APP_ID = "Office365"

    REQUIRED_APPS = {SHAREPOINT_APP_ID, EXCHANGE_APP_ID}
    MODERN_CLIENT_APP_TYPES = {
        ClientAppType.BROWSER,
        ClientAppType.MOBILE_APPS_AND_DESKTOP_CLIENTS,
    }

    def _targets_all_client_apps(self, client_app_types: list[ClientAppType]) -> bool:
        """Check if the policy targets all modern client app types.

        Returns True if the policy includes ALL explicitly or both
        Browser and Mobile apps and desktop clients.
        """
        client_app_set = set(client_app_types)
        if ClientAppType.ALL in client_app_set:
            return True
        return self.MODERN_CLIENT_APP_TYPES.issubset(client_app_set)

    def _targets_required_apps(self, included_applications: list[str]) -> bool:
        """Check if the policy targets the required applications.

        Returns True if the policy includes Office365 (the suite) or both
        SharePoint Online and Exchange Online individually.
        """
        if self.OFFICE365_APP_ID in included_applications:
            return True
        return self.REQUIRED_APPS.issubset(set(included_applications))

    def execute(self) -> list[CheckReportM365]:
        """Execute the check for application enforced restrictions in Conditional Access policies.

        Returns:
            list[CheckReportM365]: A list containing the result of the check.
        """
        findings = []
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = "No Conditional Access Policy enforces application restrictions for unmanaged devices."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if "All" not in policy.conditions.user_conditions.included_users:
                continue

            if not self._targets_all_client_apps(policy.conditions.client_app_types):
                continue

            if not self._targets_required_apps(
                policy.conditions.application_conditions.included_applications
            ):
                continue

            if (
                not policy.session_controls.application_enforced_restrictions
                or not policy.session_controls.application_enforced_restrictions.is_enabled
            ):
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )
            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy {policy.display_name} reports application enforced restrictions but does not enforce them."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy {policy.display_name} enforces application restrictions for unmanaged devices."
                break

        findings.append(report)
        return findings

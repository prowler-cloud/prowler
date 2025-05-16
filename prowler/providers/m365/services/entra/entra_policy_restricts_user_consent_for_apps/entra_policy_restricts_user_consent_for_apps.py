from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_policy_restricts_user_consent_for_apps(Check):
    """Check if the authorization policy restricts users from consenting apps.

    This check verifies whether the default user role permissions in Microsoft Entra
    prevent users from consenting to apps that access company data on their behalf.
    If such consent is disabled, the check passes.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for user consent restrictions.

        Returns:
            List[CheckReportM365]: A list containing the result of the check.
        """
        findings = []
        auth_policy = entra_client.authorization_policy

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=auth_policy if auth_policy else {},
            resource_name=auth_policy.name if auth_policy else "Authorization Policy",
            resource_id=auth_policy.id if auth_policy else "authorizationPolicy",
        )
        report.status = "FAIL"
        report.status_extended = (
            "Entra allows users to consent apps accessing company data on their behalf."
        )

        if getattr(auth_policy, "default_user_role_permissions", None) and not any(
            "ManagePermissionGrantsForSelf" in policy_assigned
            for policy_assigned in getattr(
                auth_policy.default_user_role_permissions,
                "permission_grant_policies_assigned",
                ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"],
            )
        ):
            report.status = "PASS"
            report.status_extended = "Entra does not allow users to consent apps accessing company data on their behalf."

        findings.append(report)
        return findings

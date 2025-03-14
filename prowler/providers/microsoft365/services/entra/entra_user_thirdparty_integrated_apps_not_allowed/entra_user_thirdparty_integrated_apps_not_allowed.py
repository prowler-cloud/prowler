from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client


class entra_user_thirdparty_integrated_apps_not_allowed(Check):
    """Check if third-party integrated apps are not allowed for non-admin users in Entra.

    This check verifies that non-admin users are not allowed to create third-party apps.
    If the policy allows app creation, the check fails.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """Execute the check to ensure third-party integrated apps are not allowed for non-admin users.

        This method checks if the authorization policy allows non-admin users to create apps.
        If the policy allows app creation, the check fails. Otherwise, the check passes.

        Returns:
            List[CheckReportMicrosoft365]: A list containing the result of the check for app creation policy.
        """
        findings = []
        auth_policy = entra_client.authorization_policy

        if auth_policy:
            report = CheckReportMicrosoft365(
                metadata=self.metadata(),
                resource=auth_policy if auth_policy else {},
                resource_name=(
                    auth_policy.name if auth_policy else "Authorization Policy"
                ),
                resource_id=auth_policy.id if auth_policy else "authorizationPolicy",
            )
            if getattr(
                auth_policy, "default_user_role_permissions", None
            ) and not getattr(
                auth_policy.default_user_role_permissions,
                "allowed_to_create_apps",
                True,
            ):
                report.status = "PASS"
                report.status_extended = "App creation is disabled for non-admin users."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "App creation is not disabled for non-admin users."
                )

            findings.append(report)

        return findings

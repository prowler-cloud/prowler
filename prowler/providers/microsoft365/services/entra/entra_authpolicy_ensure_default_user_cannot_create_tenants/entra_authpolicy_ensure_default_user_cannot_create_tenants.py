from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client


class entra_authpolicy_ensure_default_user_cannot_create_tenants(Check):
    """Check if default users are restricted from creating tenants.

    This check verifies whether the authorization policy prevents non-admin users
    from creating new tenants in Microsoft Entra ID.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """Execute the check for tenant creation restrictions.

        This method examines the authorization policy settings to determine if
        non-admin users are allowed to create new tenants. If tenant creation is
        restricted, the check passes.

        Returns:
            List[Check_Report_Microsoft365]: A list containing the result of the check.
        """
        findings = []
        auth_policy = entra_client.authorization_policy

        report = CheckReportMicrosoft365(
            metadata=self.metadata(),
            resource=auth_policy if auth_policy else {},
            resource_name=auth_policy.name if auth_policy else "Authorization Policy",
            resource_id=auth_policy.id if auth_policy else "authorizationPolicy",
        )
        report.status = "FAIL"
        report.status_extended = "Tenant creation is not disabled for non-admin users."

        if getattr(
            entra_client.authorization_policy, "default_user_role_permissions", None
        ) and not getattr(
            entra_client.authorization_policy.default_user_role_permissions,
            "allowed_to_create_tenants",
            True,
        ):
            report.status = "PASS"
            report.status_extended = "Tenant creation is disabled for non-admin users."

        findings.append(report)
        return findings

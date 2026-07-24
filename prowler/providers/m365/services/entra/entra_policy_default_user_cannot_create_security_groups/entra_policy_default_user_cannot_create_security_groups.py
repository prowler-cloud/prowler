from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_policy_default_user_cannot_create_security_groups(Check):
    """Check if default users are restricted from creating security groups.

    This check verifies whether the authorization policy prevents non-admin users
    from creating security groups in Microsoft Entra ID.

    - PASS: Non-admin users cannot create security groups.
    - FAIL: Non-admin users are allowed to create security groups.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for security group creation restrictions.

        This method examines the authorization policy settings to determine if
        non-admin users are allowed to create security groups. If security group
        creation is restricted, the check passes.

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
            "Non-admin users are allowed to create security groups."
        )

        if getattr(
            entra_client.authorization_policy, "default_user_role_permissions", None
        ) and not getattr(
            entra_client.authorization_policy.default_user_role_permissions,
            "allowed_to_create_security_groups",
            True,
        ):
            report.status = "PASS"
            report.status_extended = (
                "Non-admin users are not allowed to create security groups."
            )

        findings.append(report)
        return findings

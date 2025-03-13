from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client
from prowler.providers.microsoft365.services.entra.entra_service import AuthPolicyRoles


class entra_auth_policy_guest_users_access_restrictions(Check):
    """Check if guest user access is restricted to their own directory objects.

    This check verifies whether the authorization policy is configured so that guest users
    are limited to accessing only the properties and memberships of their own directory objects.
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """
        Execute the guest user access restriction check.

        This method retrieves the authorization policy from the Microsoft365 Entra client,
        and then checks if the 'guest_user_role_id' matches the predefined restricted role ID.
        If it matches, the check passes; otherwise, it fails.

        Returns:
            List[CheckReportMicrosoft365]: A list containing a single check report detailing
            the status and details of the guest user access restriction.
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
        report.status_extended = "Guest user access is not restricted to properties and memberships of their own directory objects"

        if (
            getattr(auth_policy, "guest_user_role_id", None)
            == AuthPolicyRoles.GUEST_USER_ACCESS_RESTRICTED.value
        ) or (
            getattr(auth_policy, "guest_user_role_id", None)
            == AuthPolicyRoles.GUEST_USER.value
        ):
            report.status = "PASS"
            report.status_extended = "Guest user access is restricted to properties and memberships of their own directory objects"

        findings.append(report)
        return findings

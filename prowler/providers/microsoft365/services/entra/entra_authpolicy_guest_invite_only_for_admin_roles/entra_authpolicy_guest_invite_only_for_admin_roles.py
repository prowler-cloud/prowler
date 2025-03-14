from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client
from prowler.providers.microsoft365.services.entra.entra_service import InvitationsFrom


class entra_authpolicy_guest_invite_only_for_admin_roles(Check):
    """Check if guest invitations are restricted to users with specific administrative roles.

    This check verifies the `guest_invite_settings` property of the authorization policy.
    If the setting is set to either "adminsAndGuestInviters" or "none", guest invitations
    are limited accordingly. Otherwise, they are not restricted.
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """
        Execute the guest invitation restriction check.

        Retrieves the authorization policy from the Microsoft Entra client and checks
        whether the 'guest_invite_settings' is set to restrict invitations to users with
        specific administrative roles only.

        Returns:
            List[CheckReportMicrosoft365]: A list containing a single check report that
            details the pass/fail status and description.
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
        report.status_extended = "Guest invitations are not restricted to users with specific administrative roles only."

        if (
            getattr(auth_policy, "guest_invite_settings", None)
            == InvitationsFrom.ADMINS_AND_GUEST_INVITERS.value
        ) or (
            getattr(auth_policy, "guest_invite_settings", None)
            == InvitationsFrom.NONE.value
        ):
            report.status = "PASS"
            report.status_extended = "Guest invitations are restricted to users with specific administrative roles only."

        findings.append(report)
        return findings

from uuid import UUID

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_policy_guest_user_access_restricted_to_own_directory_objects(Check):
    def execute(self) -> Check_Report_Azure:
        GUEST_USER_ACCESS_RESTRICTICTED = UUID("2af84b1e-32c8-42b7-82bc-daa82404023b")
        findings = []

        for tenant_domain, auth_policy in entra_client.authorization_policy.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "FAIL"
            report.subscription = f"Tenant: '{tenant_domain}'"
            report.resource_name = auth_policy.name
            report.resource_id = auth_policy.id
            report.status_extended = "Guest user access is not restricted to properties and memberships of their own directory objects"

            if auth_policy.guest_user_role_id == GUEST_USER_ACCESS_RESTRICTICTED:
                report.status = "PASS"
                report.status_extended = "Guest user access is restricted to properties and memberships of their own directory objects"

            findings.append(report)

        return findings


"""
FAIL
{
    "guestUserRoleId": "a0b1b346-4d3e-4e8b-98f8-753987be4970",
    "allowInvitesFrom": "adminsAndGuestInviters"
}
{
    "guestUserRoleId": "10dae51f-b6af-4016-8d66-8c2a99b929b3",
    "allowInvitesFrom": "adminsAndGuestInviters"
}
PASS
{
    "guestUserRoleId": "2af84b1e-32c8-42b7-82bc-daa82404023b",
    "allowInvitesFrom": "adminsAndGuestInviters"
}
"""

from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client
from prowler.providers.microsoft365.services.entra.entra_service import AdminRoles


class entra_admin_users_cloud_only(Check):
    """
    Check to ensure that there are no admin accounts with non-cloud-only accounts in Microsoft 365.
    This check verifies if any user with admin roles has an on-premises synchronized account.
    If such users are found, the check will fail.
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """
        Execute the check to identify admin accounts with non-cloud-only accounts.
        Returns:
            List[CheckReportMicrosoft365]: A list containing the check report with the status and details.
        """
        findings = []
        if entra_client.users:
            non_cloud_admins = []
            for user_id, user in entra_client.users.items():
                for role in user.directory_roles_ids:
                    if (
                        role in {admin_role.value for admin_role in AdminRoles}
                        and user.on_premises_sync_enabled
                    ):
                        non_cloud_admins.append(user_id)

            report = CheckReportMicrosoft365(
                metadata=self.metadata(),
                resource={},
                resource_name="Cloud-only account",
                resource_id="cloudOnlyAccount",
            )
            report.status = "PASS"
            report.status_extended = (
                "There is no admin users with a non-cloud-only account."
            )

            if non_cloud_admins:
                report.status = "FAIL"
                ids_str = ", ".join(non_cloud_admins)
                report.status_extended = (
                    f"Users with admin roles have non-cloud-only accounts: {ids_str}"
                )

            findings.append(report)
        return findings

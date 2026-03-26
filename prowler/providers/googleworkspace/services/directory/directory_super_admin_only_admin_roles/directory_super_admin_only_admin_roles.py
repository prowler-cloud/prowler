from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.directory.directory_client import (
    directory_client,
)


class directory_super_admin_only_admin_roles(Check):
    """Check that super admin accounts are used only for super admin activities

    This check verifies that no user has both Super Admin and Delegated Admin roles.
    Super admins should have separate accounts for daily activities to follow least privilege.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if directory_client.users:
            dual_role_admins = [
                user.email
                for user in directory_client.users.values()
                if user.is_admin and user.is_delegated_admin
            ]

            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=directory_client.provider.identity,
                resource_name=directory_client.provider.identity.domain,
                resource_id=directory_client.provider.identity.customer_id,
                customer_id=directory_client.provider.identity.customer_id,
                location="global",
            )

            if dual_role_admins:
                emails_str = ", ".join(dual_role_admins)
                report.status = "FAIL"
                report.status_extended = (
                    f"Super admin accounts also holding delegated admin roles: {emails_str}. "
                    f"Super admin accounts should be used only for super admin activities."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"All super admin accounts in domain {directory_client.provider.identity.domain} "
                    f"are used only for super admin activities."
                )

            findings.append(report)

        return findings

from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.directory.directory_client import (
    directory_client,
)


class directory_super_admin_only_admin_roles(Check):
    """Check that super admin accounts are used only for super admin activities

    This check verifies that no super admin user has additional admin roles assigned
    beyond the Super Admin role. Super admins should have separate accounts for daily
    activities to follow least privilege.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if directory_client.users:
            dual_role_admins = {}
            for user in directory_client.users.values():
                if user.is_admin:
                    extra_roles = [
                        r for r in user.role_assignments if r != "Super Admin"
                    ]
                    if extra_roles:
                        dual_role_admins[user.email] = extra_roles

            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=directory_client.provider.identity,
                resource_name=directory_client.provider.identity.domain,
                resource_id=directory_client.provider.identity.customer_id,
                customer_id=directory_client.provider.identity.customer_id,
                location="global",
            )

            if dual_role_admins:
                details = ", ".join(
                    f"{email} ({', '.join(roles)})"
                    for email, roles in dual_role_admins.items()
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"Super admin accounts also holding additional admin roles: {details}. "
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

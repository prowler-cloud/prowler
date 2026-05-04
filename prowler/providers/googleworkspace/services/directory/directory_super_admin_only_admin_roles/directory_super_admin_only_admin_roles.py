from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.models import GoogleWorkspaceResource
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
            for user in directory_client.users.values():
                if user.is_admin:
                    extra_roles = [
                        r.description or r.name
                        for r in user.role_assignments
                        if not r.is_super_admin_role
                    ]
                    if extra_roles:
                        report = CheckReportGoogleWorkspace(
                            metadata=self.metadata(),
                            resource=GoogleWorkspaceResource.from_user(
                                user,
                                directory_client.provider.identity.customer_id,
                            ),
                        )
                        details = ", ".join(extra_roles)
                        report.status = "FAIL"
                        report.status_extended = (
                            f"Super admin account {user.email} also holds additional admin roles: "
                            f"{details}. Super admin accounts should be used only for "
                            f"super admin activities."
                        )
                        findings.append(report)

            if not findings:
                report = CheckReportGoogleWorkspace(
                    metadata=self.metadata(),
                    resource=directory_client.provider.domain_resource,
                )
                report.status = "PASS"
                report.status_extended = (
                    f"All super admin accounts in domain {directory_client.provider.identity.domain} "
                    f"are used only for super admin activities."
                )
                findings.append(report)

        return findings

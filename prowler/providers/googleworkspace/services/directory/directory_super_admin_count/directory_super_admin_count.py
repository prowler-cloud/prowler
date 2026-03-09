from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.directory.directory_client import (
    directory_client,
)


class directory_super_admin_count(Check):
    """Check that the number of super admins is between 2 and 4

    This check verifies that the Google Workspace domain has between 2 and 4 super administrators.
    Having too few admins creates a single point of failure, while too many increases security risk.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        super_admins = [
            user for user in directory_client.users.values() if user.is_admin
        ]
        admin_count = len(super_admins)

        report = CheckReportGoogleWorkspace(
            metadata=self.metadata(),
            resource=directory_client.provider.identity,
            resource_name=directory_client.provider.identity.domain,
            resource_id=directory_client.provider.identity.customer_id,
            customer_id=directory_client.provider.identity.customer_id,
            location="global",
        )

        if 2 <= admin_count <= 4:
            report.status = "PASS"
            report.status_extended = (
                f"Domain {directory_client.provider.identity.domain} has {admin_count} super administrator(s), "
                f"which is within the recommended range of 2-4."
            )
        else:
            report.status = "FAIL"
            if admin_count < 2:
                report.status_extended = (
                    f"Domain {directory_client.provider.identity.domain} has only {admin_count} super administrator(s). "
                    f"It is recommended to have between 2 and 4 super admins to avoid single point of failure."
                )
            else:
                report.status_extended = (
                    f"Domain {directory_client.provider.identity.domain} has {admin_count} super administrator(s). "
                    f"It is recommended to have between 2 and 4 super admins to minimize security risk."
                )

        findings.append(report)
        return findings

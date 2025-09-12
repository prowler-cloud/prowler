from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.admincenter.admincenter_client import (
    admincenter_client,
)


class admincenter_users_between_two_and_four_global_admins(Check):
    """Check if there are between two and four Global Administrators in Microsoft Admin Center.

    This check verifies that the number of users with the 'Global Administrator' role is
    between 2 and 4, inclusive. If there are fewer than two or more than four, the check fails.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for the number of Global Administrators.

        This method checks if the number of users with the 'Global Administrator' role
        is between two and four. If the condition is met, the check passes; otherwise, it fails.

        Returns:
            List[CheckReportM365]: A list containing the result of the check for the Global Administrators.
        """
        findings = []
        directory_roles = admincenter_client.directory_roles
        global_admin_role = directory_roles.get("Global Administrator", {})

        if global_admin_role:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=global_admin_role,
                resource_name=global_admin_role.name,
                resource_id=global_admin_role.id,
            )
            report.status = "FAIL"
            report.status_extended = (
                "There are not between two and four global administrators."
            )

            num_global_admins = len(getattr(global_admin_role, "members", []))
            if 1 < num_global_admins < 5:
                report.status = "PASS"
                report.status_extended = (
                    f"There are {num_global_admins} global administrators."
                )
            else:
                report.status_extended = f"There are {num_global_admins} global administrators. It should be more than one and less than five."

            findings.append(report)

        return findings

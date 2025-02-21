from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.admincenter.admincenter_client import (
    admincenter_client,
)


class admincenter_users_admins_reduced_license_footprint(Check):
    """Check if users with administrative roles have a reduced license footprint.

    This check ensures that users with administrative roles (like Global Administrator)
    have valid licenses, specifically one of the allowed licenses. If a user with
    administrative roles has an invalid license, the check fails.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """Execute the check for users with administrative roles and their licenses.

        This method iterates over all users and checks if those with administrative roles
        have an allowed license. If a user has a valid license (AAD_PREMIUM or AAD_PREMIUM_P2),
        the check passes; otherwise, it fails.

        Returns:
            List[CheckReportMicrosoft365]: A list containing the result of the check for each user.
        """
        findings = []
        allowed_licenses = ["AAD_PREMIUM", "AAD_PREMIUM_P2"]
        for user in admincenter_client.users.values():
            admin_roles = ", ".join(
                [
                    role
                    for role in user.directory_roles
                    if "Administrator" in role or "Global Reader" in role
                ]
            )

            if admin_roles:
                report = CheckReportMicrosoft365(
                    metadata=self.metadata(),
                    resource=user,
                    resource_name=user.name,
                    resource_id=user.id,
                )
                report.status = "FAIL"
                report.status_extended = f"User {user.name} has administrative roles {admin_roles} and an invalid license: {user.license if user.license else None}."

                if user.license in allowed_licenses:
                    report.status = "PASS"
                    report.status_extended = f"User {user.name} has administrative roles {admin_roles} and a valid license: {user.license}."

                findings.append(report)

        return findings

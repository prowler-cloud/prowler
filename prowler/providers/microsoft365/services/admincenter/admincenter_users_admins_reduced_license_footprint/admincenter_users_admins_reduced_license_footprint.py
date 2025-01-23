from prowler.lib.check.models import Check, Check_Report_Microsoft365
from prowler.providers.microsoft365.services.admincenter.admincenter_client import (
    admincenter_client,
)


class admincenter_users_admins_reduced_license_footprint(Check):
    def execute(self) -> Check_Report_Microsoft365:
        findings = []
        allowed_licenses = ["AAD_PREMIUM", "AAD_PREMIUM_P2"]
        for user in admincenter_client.users.values():
            admin_roles = ", ".join(
                [
                    role
                    for role in user.directory_roles
                    if "Administrator" in role or "Globar Reader" in role
                ]
            )

            if admin_roles:
                report = Check_Report_Microsoft365(self.metadata())
                report.resource_id = user.id
                report.resource_name = user.name
                report.status = "FAIL"
                report.status_extended = f"User {user.name} has administrative roles {admin_roles} and an invalid license {user.license if user.license else ''}."

                if user.license in allowed_licenses:
                    report.status = "PASS"
                    report.status_extended = f"User {user.name} has administrative roles {admin_roles} and a valid license: {user.license}."

                findings.append(report)

        return findings

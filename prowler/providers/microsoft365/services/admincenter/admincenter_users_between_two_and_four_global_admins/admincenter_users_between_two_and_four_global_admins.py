from prowler.lib.check.models import Check, Check_Report_Microsoft365
from prowler.providers.microsoft365.services.admincenter.admincenter_client import (
    admincenter_client,
)


class admincenter_users_between_two_and_four_global_admins(Check):
    def execute(self) -> Check_Report_Microsoft365:
        findings = []

        directory_roles = admincenter_client.directory_roles
        report = Check_Report_Microsoft365(self.metadata())
        report.status = "FAIL"
        report.resource_name = "Global Administrator"

        if "Global Administrator" in directory_roles:
            report.resource_id = getattr(
                directory_roles["Global Administrator"],
                "id",
                "Global Administrator",
            )

            num_global_admins = len(
                getattr(directory_roles["Global Administrator"], "members", [])
            )

            if num_global_admins >= 2 and num_global_admins < 5:
                report.status = "PASS"
                report.status_extended = (
                    f"There are {num_global_admins} global administrators."
                )
            else:
                report.status_extended = f"There are {num_global_admins} global administrators. It should be more than one and less than five."

            findings.append(report)

        return findings

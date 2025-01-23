from prowler.lib.check.models import Check, Check_Report_Microsoft365
from prowler.providers.microsoft365.services.admincenter.admincenter_client import (
    admincenter_client,
)


class admincenter_groups_not_public_visibility(Check):
    def execute(self) -> Check_Report_Microsoft365:
        findings = []
        for group in admincenter_client.groups.values():
            report = Check_Report_Microsoft365(self.metadata())
            report.resource_id = group.id
            report.resource_name = group.name
            report.status = "FAIL"
            report.status_extended = f"Group {group.name} has {group.visibility} visibility and should be Private."

            if group.visibility != "Public":
                report.status = "PASS"
                report.status_extended = (
                    f"Group {group.name} has {group.visibility} visibility."
                )

            findings.append(report)

        return findings

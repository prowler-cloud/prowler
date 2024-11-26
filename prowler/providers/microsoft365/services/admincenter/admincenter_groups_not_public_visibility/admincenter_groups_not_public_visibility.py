from prowler.lib.check.models import Check, Check_Report_Microsoft365
from prowler.providers.microsoft365.services.admincenter.admincenter_client import (
    admincenter_client,
)


class admincenter_groups_not_public_visibility(Check):
    def execute(self) -> Check_Report_Microsoft365:
        findings = []
        allowed_licenses = ["AAD_PREMIUM", "AAD_PREMIUM_P2"]
        for tenant_domain, groups in admincenter_client.groups.items():
            for group_id, group in groups.items():
                admin_roles = [
                    role
                    for role in group.directory_roles
                    if "Administrator" in role or "Globar Reader" in role
                ]

                if admin_roles:
                    report = Check_Report_Microsoft365(self.metadata())
                    report.resource_id = group.id
                    report.resource_name = group.name
                    report.status = "FAIL"
                    report.status_extended = f"group {group.name} has administrative roles {admin_roles} and license {group.license}."

                    if group.license in allowed_licenses:
                        report.status = "PASS"
                        report.status_extended = f"group {group.name} has administrative roles {admin_roles} and a valid license: {group.license}."

                    findings.append(report)

        return findings

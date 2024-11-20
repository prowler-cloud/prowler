from prowler.lib.check.models import Check, Check_Report_Microsoft365
from prowler.providers.microsoft365.services.users.users_client import users_client


class users_administrative_accounts_cloud_only(Check):
    def execute(self) -> Check_Report_Microsoft365:
        findings = []

        for tenant_domain, directory_roles in users_client.directory_roles.items():
            for role_name, directory_role in directory_roles.items():
                report = Check_Report_Microsoft365(self.metadata())
                report.subscription = f"Tenant: {tenant_domain}"
                report.resource_name = role_name
                report.resource_id = directory_role.id
                report.status = "PASS"

                non_compliant_members = [
                    member
                    for member in directory_roles.members
                    if member.on_premises_sync_enabled
                ]

                if non_compliant_members:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"The following administrators in role '{role_name}' "
                        f"are synchronized with on-premises: "
                        f"{', '.join([member.name for member in non_compliant_members])}."
                    )
                else:
                    report.status_extended = (
                        f"All administrators in role '{role_name}' are cloud-only."
                    )

                findings.append(report)

        return findings

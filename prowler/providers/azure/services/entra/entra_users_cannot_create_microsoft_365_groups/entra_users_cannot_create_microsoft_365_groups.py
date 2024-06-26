from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_users_cannot_create_microsoft_365_groups(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, group_settings in entra_client.group_settings.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "FAIL"
            report.subscription = f"Tenant: {tenant_domain}"
            report.resource_name = "Microsoft365 Groups"
            report.resource_id = "Microsoft365 Groups"
            report.status_extended = "Users can create Microsoft 365 groups."

            for group_setting in group_settings.values():
                if group_setting.name == "Group.Unified":
                    for setting_value in group_setting.settings:
                        if (
                            getattr(setting_value, "name", "") == "EnableGroupCreation"
                            and setting_value.value != "true"
                        ):
                            report.status = "PASS"
                            report.status_extended = (
                                "Users cannot create Microsoft 365 groups."
                            )
                            break

            findings.append(report)

        return findings

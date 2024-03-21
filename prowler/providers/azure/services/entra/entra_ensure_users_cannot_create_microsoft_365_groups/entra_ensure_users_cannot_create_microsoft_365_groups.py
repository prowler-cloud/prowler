from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_ensure_users_cannot_create_microsoft_365_groups(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, group_settings in entra_client.group_settings.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "FAIL"
            report.subscription = f"Tenant: '{tenant_domain}'"
            report.resource_name = "Group.Unified"
            report.resource_id = "Group.Unified"
            report.status_extended = "Users can create Microsoft 365 groups."

            for group_setting_id, group_setting in group_settings.items():
                if group_setting.name == "Group.Unified":
                    for setting_value in group_setting.settings:
                        if getattr(setting_value, "name", "") == "EnableGroupCreation":
                            report.resource_name = group_setting.name
                            report.resource_id = group_setting_id

                            if setting_value.value != "true":
                                report.status = "PASS"
                                report.status_extended = (
                                    "Users cannot create Microsoft 365 groups."
                                )

                            break

            findings.append(report)

        return findings

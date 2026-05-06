from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_users_cannot_create_microsoft_365_groups(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        if entra_client.resource_groups:
            for tenant in entra_client.clients:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = tenant
                report.resource_name = "Not Applicable"
                report.resource_id = "Not Applicable"
                report.status = "MANUAL"
                report.status_extended = f"Tenant '{tenant}': this check is tenant-scoped and cannot be evaluated when --azure-resource-group is active. Re-run without --azure-resource-group to get full results."
                findings.append(report)
            return findings

        tenant_id = entra_client.tenant_ids[0]

        for tenant_domain, group_settings in entra_client.group_settings.items():
            group_unified_found = False
            for group_setting in group_settings.values():
                if group_setting.name == "Group.Unified":
                    group_unified_found = True
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=group_setting
                    )
                    report.subscription = f"Tenant: {tenant_domain}"
                    report.status = "FAIL"
                    report.status_extended = "Users can create Microsoft 365 groups."

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
                    break

            if not group_unified_found:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = f"Tenant: {tenant_domain}"
                report.resource_name = tenant_domain
                report.resource_id = tenant_id
                report.status = "FAIL"
                report.status_extended = "Users can create Microsoft 365 groups."
                findings.append(report)

        return findings

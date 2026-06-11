from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.databricks.databricks_client import databricks_client


class databricks_workspace_public_network_access_disabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, items in databricks_client.workspaces.items():
            for item_id, resource in items.items():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=resource
                )
                report.subscription = subscription_name
                report.resource_name = resource.name
                report.resource_id = resource.id
                report.location = resource.location

                if resource.public_network_access == "Disabled":
                    report.status = "PASS"
                    report.status_extended = (
                        f"{resource.name} has public network access disabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"{resource.name} has public network access enabled."
                    )

                findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.databricks.databricks_client import databricks_client


class databricks_workspace_no_public_ip_enabled(Check):
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

                if resource.no_public_ip_enabled:
                    report.status = "PASS"
                    report.status_extended = (
                        f"{resource.name} has secure cluster connectivity (no public IP) enabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"{resource.name} does not have secure cluster connectivity enabled."
                    )

                findings.append(report)

        return findings

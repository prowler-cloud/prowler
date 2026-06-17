from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.databricks.databricks_client import (
    databricks_client,
)


class databricks_workspace_public_network_access_disabled(Check):
    def execute(self) -> list[Check_Report_Azure]:
        findings = []

        for subscription_name, workspaces in databricks_client.workspaces.items():
            for resource in workspaces.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=resource)
                report.subscription = subscription_name

                if resource.public_network_access == "Disabled":
                    report.status = "PASS"
                    report.status_extended = f"Databricks workspace {resource.name} from subscription {subscription_name} has public network access disabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Databricks workspace {resource.name} from subscription {subscription_name} has public network access enabled."

                findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.databricks.databricks_client import (
    databricks_client,
)


class databricks_workspace_public_network_access_disabled(Check):
    """
    Ensure Azure Databricks workspaces have public network access disabled.

    This check evaluates whether each Azure Databricks workspace in the subscription restricts connectivity to private endpoints by disabling public network access.

    - PASS: The workspace has public network access disabled (public_network_access is "Disabled").
    - FAIL: The workspace has public network access enabled (or the value is not set).
    """

    def execute(self):
        findings = []
        for subscription, workspaces in databricks_client.workspaces.items():
            subscription_name = databricks_client.subscriptions.get(
                subscription, subscription
            )
            for workspace in workspaces.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=workspace
                )
                report.subscription = subscription
                if workspace.public_network_access == "Disabled":
                    report.status = "PASS"
                    report.status_extended = f"Databricks workspace {workspace.name} in subscription {subscription_name} ({subscription}) has public network access disabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Databricks workspace {workspace.name} in subscription {subscription_name} ({subscription}) has public network access enabled."
                findings.append(report)
        return findings

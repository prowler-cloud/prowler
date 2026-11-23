from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.databricks.databricks_client import (
    databricks_client,
)

APPROVED_STATUS = "approved"


class databricks_workspace_uses_private_endpoint(Check):
    """Databricks workspace has an approved private endpoint connection."""

    def execute(self) -> list[Check_Report_Azure]:
        """Evaluate private endpoint connections on every Databricks workspace.

        Pending, rejected and disconnected connections carry no traffic, so
        only an approved connection passes.

        Returns:
            One finding per workspace.
        """
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
                if any(
                    status.lower() == APPROVED_STATUS
                    for status in workspace.private_endpoint_connection_statuses
                ):
                    report.status = "PASS"
                    report.status_extended = f"Databricks workspace {workspace.name} in subscription {subscription_name} ({subscription}) has an approved private endpoint connection."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Databricks workspace {workspace.name} in subscription {subscription_name} ({subscription}) has no approved private endpoint connection."
                findings.append(report)
        return findings

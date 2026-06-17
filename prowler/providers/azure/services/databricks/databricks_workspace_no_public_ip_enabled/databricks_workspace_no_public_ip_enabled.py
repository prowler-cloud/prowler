from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.databricks.databricks_client import (
    databricks_client,
)


class databricks_workspace_no_public_ip_enabled(Check):
    """
    Ensure Azure Databricks workspaces have secure cluster connectivity (no public IP) enabled.

    This check evaluates whether each Azure Databricks workspace in the subscription is deployed with secure cluster connectivity (No Public IP / NPIP), so cluster nodes are not assigned public IP addresses.

    Secure cluster connectivity is a classic-compute setting. Serverless workspaces do not expose it (they have no customer-managed cluster nodes with public IPs), so the workspace is reported as MANUAL for verification rather than failed.

    - PASS: The workspace has secure cluster connectivity enabled (no_public_ip_enabled is True).
    - FAIL: The workspace has secure cluster connectivity disabled (no_public_ip_enabled is False).
    - MANUAL: The workspace does not expose the setting (no_public_ip_enabled is None, e.g. serverless workspaces).
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
                if workspace.no_public_ip_enabled is None:
                    report.status = "MANUAL"
                    report.status_extended = f"Databricks workspace {workspace.name} in subscription {subscription_name} ({subscription}) does not expose secure cluster connectivity (no public IP) settings (for example, serverless workspaces have no public-IP cluster nodes); verify the network configuration manually."
                elif workspace.no_public_ip_enabled:
                    report.status = "PASS"
                    report.status_extended = f"Databricks workspace {workspace.name} in subscription {subscription_name} ({subscription}) has secure cluster connectivity (no public IP) enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Databricks workspace {workspace.name} in subscription {subscription_name} ({subscription}) does not have secure cluster connectivity (no public IP) enabled."
                findings.append(report)
        return findings

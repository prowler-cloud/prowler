from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.databricks.databricks_client import (
    databricks_client,
)


class databricks_workspace_vnet_injection_enabled(Check):
    """
    Ensure Azure Databricks workspaces are deployed in a customer-managed VNet (VNet Injection).

    This check evaluates whether each Azure Databricks workspace in the subscription is configured to use VNet Injection, meaning it is deployed in a customer-managed virtual network (VNet).

    - PASS: The workspace is deployed in a customer-managed VNet (custom_managed_vnet_id is set).
    - FAIL: The workspace is not deployed in a customer-managed VNet (VNet Injection is not enabled).
    """

    def execute(self):
        findings = []
        for subscription, workspaces in databricks_client.workspaces.items():
            for workspace in workspaces.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=workspace
                )
                report.subscription = subscription
                if workspace.custom_managed_vnet_id:
                    report.status = "PASS"
                    report.status_extended = f"Databricks workspace {workspace.name} in subscription {subscription} is deployed in a customer-managed VNet ({workspace.custom_managed_vnet_id})."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Databricks workspace {workspace.name} in subscription {subscription} is not deployed in a customer-managed VNet (VNet Injection is not enabled)."
                findings.append(report)
        return findings

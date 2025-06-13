from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.databricks.databricks_client import (
    databricks_client,
)


class databricks_workspace_cmk_encryption_enabled(Check):
    """
    Ensure Azure Databricks workspaces use customer-managed keys (CMK) for encryption at rest.

    This check evaluates whether each Azure Databricks workspace in the subscription is configured to use a customer-managed key (CMK) for encrypting data at rest.

    - PASS: The workspace has CMK encryption enabled (managed_disk_encryption is set).
    - FAIL: The workspace does not have CMK encryption enabled.
    """

    def execute(self):
        findings = []
        for subscription, workspaces in databricks_client.workspaces.items():
            for workspace in workspaces.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=workspace
                )
                report.subscription = subscription
                enc = workspace.managed_disk_encryption
                if enc:
                    report.status = "PASS"
                    report.status_extended = f"Databricks workspace {workspace.name} in subscription {subscription} has customer-managed key (CMK) encryption enabled with key {enc.key_vault_uri}/{enc.key_name}/{enc.key_version}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Databricks workspace {workspace.name} in subscription {subscription} does not have customer-managed key (CMK) encryption enabled."
                findings.append(report)
        return findings

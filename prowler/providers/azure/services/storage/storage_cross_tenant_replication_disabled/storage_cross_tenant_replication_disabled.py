from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_cross_tenant_replication_disabled(Check):
    """Check if cross-tenant replication is disabled.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> Check_Report_Azure:
        """Execute the check for cross-tenant replication.

        This method checks if cross-tenant replication is disabled. If it is, the check passes; otherwise, it fails.

        Returns:
            Check_Report_Azure: A report containing the result of the check.
        """
        findings = []
        for subscription, storage_accounts in storage_client.storage_accounts.items():
            for storage_account in storage_accounts:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=storage_account
                )
                report.subscription = subscription
                if not storage_account.allow_cross_tenant_replication:
                    report.status = "PASS"
                    report.status_extended = f"Storage account {storage_account.name} from subscription {subscription} has cross-tenant replication disabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Storage account {storage_account.name} from subscription {subscription} has cross-tenant replication enabled."
                findings.append(report)
        return findings

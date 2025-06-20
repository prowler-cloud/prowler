from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client
from prowler.providers.azure.services.storage.storage_service import ReplicationSettings


class storage_geo_redundant_enabled(Check):
    """Check if geo-redundant storage (GRS) is enabled on critical Azure Storage Accounts.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> Check_Report_Azure:
        """Execute the check for geo-redundant storage (GRS).

        This method checks if geo-redundant storage (GRS) is enabled on critical Azure Storage Accounts.

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

                if (
                    storage_account.replication_settings
                    == ReplicationSettings.STANDARD_GRS
                ):
                    report.status = "PASS"
                    report.status_extended = f"Storage account {storage_account.name} from subscription {subscription} has Geo-redundant storage (GRS) enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Storage account {storage_account.name} from subscription {subscription} does not have Geo-redundant storage (GRS) enabled."

                findings.append(report)

        return findings

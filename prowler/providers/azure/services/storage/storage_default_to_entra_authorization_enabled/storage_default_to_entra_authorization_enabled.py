from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_default_to_entra_authorization_enabled(Check):
    """Check if the default to Microsoft Entra authorization is enabled for the storage account.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).

    """

    def execute(self) -> Check_Report_Azure:
        """Execute the check for the default to Microsoft Entra authorization.

        This method checks if the default to Microsoft Entra authorization is enabled for the storage account.

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
                report.resource_name = storage_account.name
                report.resource_id = storage_account.id
                report.status = "FAIL"
                report.status_extended = f"Default to Microsoft Entra authorization is not enabled for storage account {storage_account.name}."

                if storage_account.default_to_entra_authorization:
                    report.status = "PASS"
                    report.status_extended = f"Default to Microsoft Entra authorization is enabled for storage account {storage_account.name}."

                findings.append(report)
        return findings

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_account_public_network_access_disabled(Check):
    """
    Ensure that 'Public Network Access' is 'Disabled' for storage accounts.

    This check evaluates the storage account's publicNetworkAccess property, which controls
    whether the account is reachable from public networks. It is independent from the
    'Allow Blob Anonymous Access' setting (covered by
    storage_blob_public_access_level_is_disabled).
    - PASS: The storage account has public network access disabled.
    - FAIL: The storage account has public network access enabled (or unset, which Azure treats as enabled).
    """

    def execute(self) -> list[Check_Report_Azure]:
        findings = []
        for subscription, storage_accounts in storage_client.storage_accounts.items():
            subscription_name = storage_client.subscriptions.get(
                subscription, subscription
            )
            for storage_account in storage_accounts:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=storage_account
                )
                report.subscription = subscription

                if storage_account.public_network_access == "Disabled":
                    report.status = "PASS"
                    report.status_extended = f"Storage account {storage_account.name} from subscription {subscription_name} ({subscription}) has public network access disabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Storage account {storage_account.name} from subscription {subscription_name} ({subscription}) has public network access enabled."

                findings.append(report)

        return findings

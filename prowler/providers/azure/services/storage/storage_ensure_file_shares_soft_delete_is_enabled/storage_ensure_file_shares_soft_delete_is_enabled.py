from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_ensure_file_shares_soft_delete_is_enabled(Check):
    def execute(self) -> list:
        findings = []
        for subscription, storage_accounts in storage_client.storage_accounts.items():
            for storage_account in storage_accounts:
                if (
                    hasattr(storage_account, "file_shares")
                    and storage_account.file_shares
                ):
                    for file_share in storage_account.file_shares:
                        report = Check_Report_Azure(
                            metadata=self.metadata(), resource=storage_account
                        )
                        report.subscription = subscription
                        report.resource_id = file_share.name
                        if (
                            file_share.soft_delete_enabled
                            and file_share.retention_days > 0
                        ):
                            report.status = "PASS"
                            report.status_extended = (
                                f"File share {file_share.name} in storage account {storage_account.name} "
                                f"from subscription {subscription} has soft delete enabled with a retention period of "
                                f"{file_share.retention_days} days."
                            )
                        else:
                            report.status = "FAIL"
                            report.status_extended = (
                                f"File share {file_share.name} in storage account {storage_account.name} "
                                f"from subscription {subscription} does not have soft delete enabled or has an invalid "
                                f"retention period."
                            )
                        findings.append(report)
        return findings

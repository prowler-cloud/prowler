from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_ensure_file_shares_soft_delete_is_enabled(Check):
    def execute(self) -> list:
        findings = []
        for subscription, storage_accounts in storage_client.storage_accounts.items():
            for storage_account in storage_accounts:
                if getattr(storage_account, "file_service_properties", None):
                    report = Check_Report_Azure(
                        metadata=self.metadata(),
                        resource=storage_account.file_service_properties,
                    )
                    report.subscription = subscription
                    report.resource_name = storage_account.name
                    report.location = storage_account.location

                    if (
                        storage_account.file_service_properties.share_delete_retention_policy.enabled
                    ):
                        report.status = "PASS"
                        report.status_extended = f"File share soft delete is enabled for storage account {storage_account.name} with a retention period of {storage_account.file_service_properties.share_delete_retention_policy.days} days."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"File share soft delete is not enabled for storage account {storage_account.name}."

                    findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_blob_versioning_is_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, storage_accounts in storage_client.storage_accounts.items():
            for storage_account in storage_accounts:
                if storage_account.blob_properties:
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=storage_account
                    )
                    report.subscription = subscription
                    if getattr(
                        storage_account.blob_properties, "versioning_enabled", False
                    ):
                        report.status = "PASS"
                        report.status_extended = f"Storage account {storage_account.name} from subscription {subscription} has blob versioning enabled."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"Storage account {storage_account.name} from subscription {subscription} does not have blob versioning enabled."
                    findings.append(report)
        return findings

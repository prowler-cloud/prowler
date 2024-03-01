from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.monitor_client import monitor_client
from prowler.providers.azure.services.storage.storage_client import storage_client


class monitor_storage_account_with_activity_logs_is_private(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            diagnostic_settings,
        ) in monitor_client.diagnostics_settings.items():
            for diagnostic_setting in diagnostic_settings:
                sa_id = diagnostic_setting.storage_account_id  # sa = storage account
                elements = sa_id.split("/")
                sa_name = elements[8]
                for storage_account in storage_client.storage_accounts[
                    subscription_name
                ]:
                    if storage_account.name == sa_name:
                        report = Check_Report_Azure(self.metadata())
                        report.subscription = subscription_name
                        report.resource_name = storage_account.name
                        report.resource_id = storage_account.id
                        if storage_account.allow_blob_public_access:
                            report.status = "FAIL"
                            report.status_extended = f"Blob public access enabled in storage account {storage_account.name} storing activity logs in subscription {subscription_name}."
                        else:
                            report.status = "PASS"
                            report.status_extended = f"Blob public access disabled in storage account {storage_account.name} storing activity logs in subscription {subscription_name}."

                        findings.append(report)

        return findings

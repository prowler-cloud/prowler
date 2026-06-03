from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.monitor_client import monitor_client
from prowler.providers.azure.services.storage.storage_client import storage_client


class monitor_storage_account_with_activity_logs_is_private(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_id in monitor_client.subscriptions:
            subscription_name = monitor_client.subscriptions[subscription_id]
            if monitor_client.resource_groups:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_id
                report.resource_name = subscription_id
                report.resource_id = f"/subscriptions/{subscription_id}"
                report.status = "MANUAL"
                report.status_extended = f"Subscription '{subscription_name}' ({subscription_id}): diagnostic-setting checks are subscription-scoped and cannot be accurately evaluated with resource group filtering enabled. Re-run without --azure-resource-group to get accurate results."
                findings.append(report)
                continue

            for diagnostic_setting in monitor_client.diagnostics_settings.get(
                subscription_id, []
            ):
                for storage_account in storage_client.storage_accounts.get(
                    subscription_id, []
                ):
                    if storage_account.name == diagnostic_setting.storage_account_name:
                        report = Check_Report_Azure(
                            metadata=self.metadata(), resource=storage_account
                        )
                        report.subscription = subscription_id
                        if storage_account.allow_blob_public_access:
                            report.status = "FAIL"
                            report.status_extended = f"Blob public access enabled in storage account {storage_account.name} storing activity logs in subscription {subscription_name} ({subscription_id})."
                        else:
                            report.status = "PASS"
                            report.status_extended = f"Blob public access disabled in storage account {storage_account.name} storing activity logs in subscription {subscription_name} ({subscription_id})."

                        findings.append(report)

        return findings

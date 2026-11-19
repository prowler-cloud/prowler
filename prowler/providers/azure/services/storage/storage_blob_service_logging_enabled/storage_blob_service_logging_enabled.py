from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client
from prowler.providers.azure.services.storage.storage_service import (
    SERVICES_WITH_LOGGING,
)

REQUIRED_CATEGORIES = {"StorageRead", "StorageWrite", "StorageDelete"}


class storage_blob_service_logging_enabled(Check):
    """Ensure Blob service diagnostic logging is enabled for read, write and delete requests.

    This check evaluates whether each storage account's Blob service
    (blobServices/default) has Azure Monitor diagnostic settings with
    StorageRead, StorageWrite and StorageDelete log categories enabled,
    or the allLogs category group enabled.

    - PASS: All three required log categories (or allLogs) are enabled
      across one or more diagnostic settings.
    - FAIL: One or more required log categories are missing or disabled.
    - MANUAL: Diagnostic settings could not be retrieved for the Blob service.
    """

    def execute(self) -> list[Check_Report_Azure]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for (
            subscription_id,
            storage_accounts,
        ) in storage_client.storage_accounts.items():
            subscription_name = storage_client.subscriptions.get(
                subscription_id, subscription_id
            )
            for storage_account in storage_accounts:
                # Skip accounts without Blob service (e.g. FileStorage)
                if storage_account.kind in SERVICES_WITH_LOGGING["blob"]:
                    continue

                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=storage_account
                )
                report.subscription = subscription_id

                # If diagnostic settings could not be read, emit MANUAL
                if storage_account.blob_service_diagnostic_settings is None:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Could not retrieve Blob service diagnostic settings "
                        f"for storage account {storage_account.name} in "
                        f"subscription {subscription_name} "
                        f"({subscription_id}). Verify that the scanning "
                        f"identity has Reader access."
                    )
                    findings.append(report)
                    continue

                # Collect the union of enabled categories across all settings
                enabled_categories = set()
                all_logs_enabled = False

                for diag_setting in storage_account.blob_service_diagnostic_settings:
                    for log in diag_setting.logs:
                        if not log.enabled:
                            continue
                        if log.category_group == "allLogs":
                            all_logs_enabled = True
                        if log.category in REQUIRED_CATEGORIES:
                            enabled_categories.add(log.category)

                if all_logs_enabled or enabled_categories >= REQUIRED_CATEGORIES:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Storage account {storage_account.name} in "
                        f"subscription {subscription_name} "
                        f"({subscription_id}) has Blob service diagnostic "
                        f"logging enabled for read, write and delete requests."
                    )
                else:
                    missing = sorted(REQUIRED_CATEGORIES - enabled_categories)
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Storage account {storage_account.name} in "
                        f"subscription {subscription_name} "
                        f"({subscription_id}) does not have Blob service "
                        f"diagnostic logging enabled for: "
                        f"{', '.join(missing)}."
                    )

                findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client
from prowler.providers.azure.services.storage.storage_service import (
    SERVICES_WITH_LOGGING,
)

# Categories required to be enabled for Table service logging.
REQUIRED_CATEGORIES = {"StorageRead", "StorageWrite", "StorageDelete"}


class storage_table_service_logging_enabled(Check):
    """Ensure Storage Table service has diagnostic logging for read, write and delete requests.

    This check evaluates whether every Azure Storage account's Table service
    (tableServices/default) has diagnostic settings with the categories
    StorageRead, StorageWrite and StorageDelete enabled, or the allLogs
    category group enabled.
    - PASS: All three categories are enabled (individually or via allLogs).
    - FAIL: One or more of the required categories are missing or disabled.
    """

    def execute(self) -> list[Check_Report_Azure]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for subscription, accounts in storage_client.storage_accounts.items():
            subscription_name = storage_client.subscriptions.get(
                subscription, subscription
            )

            for account in accounts:
                # Skip account kinds that do not support a Table service.
                if account.kind in SERVICES_WITH_LOGGING["table"]:
                    continue

                report = Check_Report_Azure(metadata=self.metadata(), resource=account)
                report.subscription = subscription

                # If diagnostic settings could not be retrieved, emit MANUAL.
                if account.table_service_diagnostic_settings is None:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Could not retrieve Table service diagnostic settings "
                        f"for storage account {account.name} in subscription "
                        f"{subscription_name} ({subscription}). "
                        f"Verify that the scanning identity has "
                        f"Microsoft.Insights/diagnosticSettings/read permission."
                    )
                    findings.append(report)
                    continue

                # Collect enabled categories across all diagnostic settings.
                enabled_categories = set()
                has_all_logs = False

                for diag_setting in account.table_service_diagnostic_settings:
                    for log in diag_setting.logs:
                        if not log.enabled:
                            continue
                        if log.category_group == "allLogs":
                            has_all_logs = True
                        if log.category in REQUIRED_CATEGORIES:
                            enabled_categories.add(log.category)

                if has_all_logs or enabled_categories >= REQUIRED_CATEGORIES:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Storage account {account.name} in subscription "
                        f"{subscription_name} ({subscription}) has Table service "
                        f"logging enabled for StorageRead, StorageWrite and "
                        f"StorageDelete."
                    )
                else:
                    missing = sorted(REQUIRED_CATEGORIES - enabled_categories)
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Storage account {account.name} in subscription "
                        f"{subscription_name} ({subscription}) does not have "
                        f"Table service logging enabled for: "
                        f"{', '.join(missing)}."
                    )

                findings.append(report)

        return findings

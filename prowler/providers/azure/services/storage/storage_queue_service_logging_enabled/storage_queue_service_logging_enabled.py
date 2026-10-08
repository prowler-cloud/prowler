from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client
from prowler.providers.azure.services.storage.storage_service import (
    SERVICES_WITH_LOGGING,
)

# Required log categories for Queue service compliance.
_REQUIRED_CATEGORIES = {"StorageRead", "StorageWrite", "StorageDelete"}


class storage_queue_service_logging_enabled(Check):
    """Ensure Queue service diagnostic logging is enabled for storage accounts.

    This check evaluates whether each storage account has Azure Monitor
    diagnostic settings on its Queue service (``queueServices/default``)
    with the **StorageRead**, **StorageWrite**, and **StorageDelete** log
    categories enabled.  The ``allLogs`` category group also satisfies
    the requirement.

    - PASS: All three required log categories (or ``allLogs``) are enabled
      across the account's Queue service diagnostic settings.
    - FAIL: One or more required log categories are missing or disabled.
    """

    def execute(self) -> list[Check_Report_Azure]:
        """Execute the Queue service logging check.

        Returns:
            A list of findings, one per eligible storage account.
        """
        findings = []
        for subscription, storage_accounts in storage_client.storage_accounts.items():
            subscription_name = storage_client.subscriptions.get(
                subscription, subscription
            )
            for storage_account in storage_accounts:
                # Skip account kinds that do not have a Queue service.
                if storage_account.kind in SERVICES_WITH_LOGGING["queue"]:
                    continue

                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=storage_account
                )
                report.subscription = subscription

                diag_settings = storage_account.queue_service_diagnostic_settings

                # Data could not be retrieved — emit MANUAL.
                if diag_settings is None:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Storage account {storage_account.name} from subscription "
                        f"{subscription_name} ({subscription}) could not have its "
                        f"Queue service diagnostic settings evaluated. Verify that "
                        f"the scanning identity has the Reader role."
                    )
                    findings.append(report)
                    continue

                # Collect enabled categories across all diagnostic settings.
                enabled_categories = set()
                all_logs_enabled = False
                for setting in diag_settings:
                    for log in setting.logs:
                        if log.enabled:
                            if log.category_group == "allLogs":
                                all_logs_enabled = True
                            if log.category and log.category in _REQUIRED_CATEGORIES:
                                enabled_categories.add(log.category)

                if all_logs_enabled or _REQUIRED_CATEGORIES <= enabled_categories:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Storage account {storage_account.name} from subscription "
                        f"{subscription_name} ({subscription}) has Queue service "
                        f"logging enabled for all required categories."
                    )
                else:
                    missing = _REQUIRED_CATEGORIES - enabled_categories
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Storage account {storage_account.name} from subscription "
                        f"{subscription_name} ({subscription}) has Queue service "
                        f"logging disabled or missing for categories: "
                        f"{', '.join(sorted(missing))}."
                    )

                findings.append(report)
        return findings

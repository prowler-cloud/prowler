from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aiservices.aiservices_client import (
    aiservices_client,
)

AUDIT_CATEGORY = "audit"
AUDIT_CATEGORY_GROUPS = {"audit", "alllogs"}


def sends_audit_logs(diagnostic_setting) -> bool:
    """Tell whether a diagnostic setting sends AI services audit logs.

    Args:
        diagnostic_setting: Monitor `DiagnosticSetting` of the account.

    Returns:
        True if the `Audit` category, or the `audit` or `allLogs` category
        group, is enabled.
    """
    return any(
        log.enabled
        and (
            (log.category or "").lower() == AUDIT_CATEGORY
            or (log.category_group or "").lower() in AUDIT_CATEGORY_GROUPS
        )
        for log in diagnostic_setting.logs
    )


class aiservices_account_diagnostic_logging_enabled(Check):
    """AI services account sends audit logs through a diagnostic setting."""

    def execute(self) -> list[Check_Report_Azure]:
        """Evaluate audit logging on every AI services account.

        Returns:
            One finding per account. MANUAL when the diagnostic settings
            could not be read.
        """
        findings = []
        for subscription_id, accounts in aiservices_client.accounts.items():
            subscription_name = aiservices_client.subscriptions.get(
                subscription_id, subscription_id
            )
            for account in accounts.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=account)
                report.subscription = subscription_id
                prefix = f"AI services account {account.name} (kind {account.kind}) from subscription {subscription_name} ({subscription_id})"
                settings = account.monitor_diagnostic_settings
                if settings is None:
                    report.status = "MANUAL"
                    report.status_extended = f"{prefix} diagnostic settings could not be read; grant Microsoft.Insights/diagnosticSettings/read (included in Reader) to evaluate audit logging."
                elif any(sends_audit_logs(setting) for setting in settings):
                    report.status = "PASS"
                    report.status_extended = (
                        f"{prefix} has a diagnostic setting that sends audit logs."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"{prefix} has no diagnostic setting that sends audit logs."
                    )
                findings.append(report)
        return findings

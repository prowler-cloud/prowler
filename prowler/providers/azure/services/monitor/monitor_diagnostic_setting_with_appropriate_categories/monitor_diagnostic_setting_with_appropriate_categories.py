from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_diagnostic_setting_with_appropriate_categories(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            diagnostic_settings,
        ) in monitor_client.diagnostics_settings.items():
            compliant_setting = None

            for diagnostic_setting in diagnostic_settings:
                administrative_enabled = False
                security_enabled = False
                alert_enabled = False
                policy_enabled = False

                for log in diagnostic_setting.logs:
                    if log.category == "Administrative" and log.enabled:
                        administrative_enabled = True
                    if log.category == "Security" and log.enabled:
                        security_enabled = True
                    if log.category == "Alert" and log.enabled:
                        alert_enabled = True
                    if log.category == "Policy" and log.enabled:
                        policy_enabled = True

                if (
                    administrative_enabled
                    and security_enabled
                    and alert_enabled
                    and policy_enabled
                ):
                    compliant_setting = diagnostic_setting
                    break

            if compliant_setting:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=compliant_setting
                )
                report.subscription = subscription_name
                report.status = "PASS"
                report.status_extended = f"Diagnostic setting {compliant_setting.name} captures appropriate categories in subscription {subscription_name}."
            else:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_name
                report.resource_name = subscription_name
                report.resource_id = (
                    f"/subscriptions/{monitor_client.subscriptions[subscription_name]}"
                )
                report.status = "FAIL"
                report.status_extended = f"No diagnostic setting captures all appropriate categories (Administrative, Security, Alert, Policy) in subscription {subscription_name}."

            findings.append(report)

        return findings

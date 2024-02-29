from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_diagnostic_setting_with_appropriate_categories(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            diagnostic_settings,
        ) in monitor_client.diagnostics_settings.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "FAIL"
            report.subscription = subscription_name
            report.resource_name = "Monitor"
            report.resource_id = "Monitor"
            report.status_extended = f"There are no diagnostic settings capturing appropiate categories in subscription {subscription_name}."
            administrative_enabled = False
            security_enabled = False
            service_health_enabled = False
            alert_enabled = False
            for diagnostic_setting in diagnostic_settings:
                if diagnostic_setting.type == "Microsoft.KeyVault/vaults":
                    # Comprobacion de que archive to a storage account esté enabled
                    pass
                for log in diagnostic_setting.logs:
                    if log.category == "Administrative" and log.enabled:
                        administrative_enabled = True
                    if log.category == "Security" and log.enabled:
                        security_enabled = True
                    if log.category == "Alert" and log.enabled:
                        service_health_enabled = True
                    if log.category == "Policy" and log.enabled:
                        alert_enabled = True

                    if (
                        administrative_enabled
                        and security_enabled
                        and service_health_enabled
                        and alert_enabled
                    ):
                        report.status = "PASS"
                        report.status_extended = f"There is at least one diagnostic setting capturing appropiate categories in subscription {subscription_name}."
                        break
                if (
                    administrative_enabled
                    and security_enabled
                    and service_health_enabled
                    and alert_enabled
                ):
                    break

            findings.append(report)

        return findings

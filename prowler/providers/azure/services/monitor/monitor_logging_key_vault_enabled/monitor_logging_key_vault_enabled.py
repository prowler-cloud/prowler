from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_logging_key_vault_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            diagnostic_settings,
        ) in monitor_client.diagnostics_settings.items():
            if not diagnostic_settings:
                report = Check_Report_Azure(self.metadata())
                report.status = "PASS"
                report.subscription = subscription_name
                report.resource_name = "Monitor"
                report.resource_id = "Monitor"
                report.status_extended = f"Logging for Azure Key Vault is enabled in subscription {subscription_name} or not necessary."
                findings.append(report)
            for diagnostic_setting in diagnostic_settings:
                print(diagnostic_setting.type)
                for log in diagnostic_setting.logs:
                    print(log.category)
                if diagnostic_setting.type == "Microsoft.KeyVault/vaults":
                    # Comprobacion de que archive to a storage account esté enabled
                    pass

        findings.append(report)

        return findings

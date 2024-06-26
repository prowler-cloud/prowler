from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_mcas_is_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            settings,
        ) in defender_client.settings.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "FAIL"
            report.subscription = subscription_name
            report.resource_name = "MCAS"
            report.resource_id = "MCAS"
            report.status_extended = f"Microsoft Defender for Cloud Apps not exists for subscription {subscription_name}."
            if "MCAS" in settings:
                report.resource_id = settings["MCAS"].resource_id
                report.status_extended = f"Microsoft Defender for Cloud Apps is disabeld for subscription {subscription_name}."
                if settings["MCAS"].enabled:
                    report.status = "PASS"
                    report.status_extended = f"Microsoft Defender for Cloud Apps is enabled for subscription {subscription_name}."

            findings.append(report)

        return findings

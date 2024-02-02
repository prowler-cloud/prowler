from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_mcas_is_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            settings,
        ) in defender_client.settings.items():
            if "MCAS" in settings:
                report = Check_Report_Azure(self.metadata())
                report.status = "PASS"
                report.subscription = subscription_name
                report.resource_name = "MCAS"
                report.resource_id = settings["MCAS"].resource_id
                report.status_extended = f"Microsoft Defender for Cloud Apps is enabled for susbscription {subscription_name}."

                if not settings["MCAS"].enabled:
                    report.status = "FAIL"
                    report.status_extended = f"Microsoft Defender for Cloud Apps is disabeld for subscription {subscription_name}."

                findings.append(report)

        return findings

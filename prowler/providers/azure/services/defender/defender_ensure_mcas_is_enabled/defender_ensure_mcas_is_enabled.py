from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_mcas_is_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            settings,
        ) in defender_client.settings.items():
            if "MCAS" not in settings:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource_metadata={}
                )
                report.subscription = subscription_name
                report.resource_name = "MCAS"
                report.resource_id = "MCAS"
                report.status = "FAIL"
                report.status_extended = f"Microsoft Defender for Cloud Apps not exists for subscription {subscription_name}."
            else:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource_metadata=settings["MCAS"]
                )
                report.subscription = subscription_name
                report.resource_name = "MCAS"
                if settings["MCAS"].enabled:
                    report.status = "PASS"
                    report.status_extended = f"Microsoft Defender for Cloud Apps is enabled for subscription {subscription_name}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Microsoft Defender for Cloud Apps is disabled for subscription {subscription_name}."

            findings.append(report)

        return findings

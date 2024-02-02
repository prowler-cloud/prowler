from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_wdatp_is_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            settings,
        ) in defender_client.settings.items():
            if "WDATP" in settings:
                report = Check_Report_Azure(self.metadata())
                report.status = "PASS"
                report.subscription = subscription_name
                report.resource_name = "WDATP"
                report.resource_id = settings["WDATP"].resource_id
                report.status_extended = f"Microsoft Defender for Endpoint integration is enabled for susbscription {subscription_name}."

                if not settings["WDATP"].enabled:
                    report.status = "FAIL"
                    report.status_extended = f"Microsoft Defender for Endpoint integration is disabeld for subscription {subscription_name}."

                findings.append(report)

        return findings

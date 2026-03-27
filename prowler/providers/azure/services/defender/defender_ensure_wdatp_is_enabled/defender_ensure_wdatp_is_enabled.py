from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_wdatp_is_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            settings,
        ) in defender_client.settings.items():
            if "WDATP" not in settings:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_name
                report.resource_name = subscription_name
                report.resource_id = (
                    f"/subscriptions/{defender_client.subscriptions[subscription_name]}"
                )
                report.status = "FAIL"
                report.status_extended = f"Microsoft Defender for Endpoint integration not exists for subscription {subscription_name}."
            else:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=settings["WDATP"]
                )
                report.subscription = subscription_name
                if settings["WDATP"].enabled:
                    report.status = "PASS"
                    report.status_extended = f"Microsoft Defender for Endpoint integration is enabled for subscription {subscription_name}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Microsoft Defender for Endpoint integration is disabled for subscription {subscription_name}."

            findings.append(report)

        return findings

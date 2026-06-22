from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_mcas_is_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_id,
            settings,
        ) in defender_client.settings.items():
            subscription_name = defender_client.subscriptions.get(
                subscription_id, subscription_id
            )
            if "MCAS" not in settings:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_id
                report.resource_name = subscription_id
                report.resource_id = f"/subscriptions/{subscription_id}"
                report.status = "FAIL"
                report.status_extended = f"Microsoft Defender for Cloud Apps not exists for subscription {subscription_name} ({subscription_id})."
            else:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=settings["MCAS"]
                )
                report.subscription = subscription_id
                if settings["MCAS"].enabled:
                    report.status = "PASS"
                    report.status_extended = f"Microsoft Defender for Cloud Apps is enabled for subscription {subscription_name} ({subscription_id})."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Microsoft Defender for Cloud Apps is disabled for subscription {subscription_name} ({subscription_id})."

            findings.append(report)

        return findings

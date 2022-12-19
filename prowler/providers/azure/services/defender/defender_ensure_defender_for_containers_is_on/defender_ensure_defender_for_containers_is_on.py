from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_defender_for_containers_is_on(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, pricings in defender_client.pricings.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "PASS"
            report.subscription = subscription
            report.resource_id = pricings["Containers"].resource_id
            report.resource_name = "Defender plan Container Registries"
            report.status_extended = f"Defender plan Defender for Containers from subscription {subscription} is set to ON (pricing tier standard)"
            if pricings["Containers"].pricing_tier != "Standard":
                report.status = "FAIL"
                report.status_extended = f"Defender plan Defender for Containers from subscription {subscription} is set to OFF (pricing tier not standard)"

            findings.append(report)
        return findings

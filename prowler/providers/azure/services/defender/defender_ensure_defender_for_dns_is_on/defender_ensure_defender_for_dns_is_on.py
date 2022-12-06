from prowler.lib.check.models import Check, Check_Report
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_defender_for_dns_is_on(Check):
    def execute(self) -> Check_Report:
        findings = []
        for subscription, pricings in defender_client.pricings.items():
            report = Check_Report(self.metadata())
            report.region = defender_client.region
            report.status = "PASS"
            report.resource_id = "Defender plan DNS"
            report.status_extended = f"Defender plan Defender for DNS from subscription {subscription} is set to ON (pricing tier standard)"
            if pricings["Dns"].pricing_tier != "Standard":
                report.status = "FAIL"
                report.status_extended = f"Defender plan Defender for DNS from subscription {subscription} is set to OFF (pricing tier not standard)"

            findings.append(report)
        return findings

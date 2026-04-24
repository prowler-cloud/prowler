from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_defender_cspm_is_on(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, pricings in defender_client.pricings.items():
            if "CloudPosture" in pricings:
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource=pricings["CloudPosture"],
                )
                report.subscription = subscription
                report.resource_name = "Defender plan CSPM"
                report.status = "PASS"
                report.status_extended = (
                    f"Defender plan CSPM from subscription {subscription} "
                    f"is set to ON (pricing tier standard)."
                )
                if pricings["CloudPosture"].pricing_tier != "Standard":
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Defender plan CSPM from subscription {subscription} "
                        f"is set to OFF (pricing tier not standard)."
                    )

                findings.append(report)
        return findings

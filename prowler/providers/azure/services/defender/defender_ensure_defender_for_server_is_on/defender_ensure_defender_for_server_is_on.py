from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_defender_for_server_is_on(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, pricings in defender_client.pricings.items():
            subscription_name = defender_client.subscriptions.get(
                subscription, subscription
            )
            if "VirtualMachines" in pricings:
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource=pricings["VirtualMachines"],
                )
                report.subscription = subscription
                report.resource_name = "Defender plan Servers"
                report.status = "PASS"
                report.status_extended = f"Defender plan Defender for Servers from subscription {subscription_name} ({subscription}) is set to ON (pricing tier standard)."
                if pricings["VirtualMachines"].pricing_tier != "Standard":
                    report.status = "FAIL"
                    report.status_extended = f"Defender plan Defender for Servers from subscription {subscription_name} ({subscription}) is set to OFF (pricing tier not standard)."

                findings.append(report)
        return findings

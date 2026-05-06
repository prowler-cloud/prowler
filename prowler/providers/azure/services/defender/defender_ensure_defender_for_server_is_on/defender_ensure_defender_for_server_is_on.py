from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_defender_for_server_is_on(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        if defender_client.resource_groups:
            for subscription in defender_client.subscriptions:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription
                report.resource_name = "Not Applicable"
                report.resource_id = "Not Applicable"
                report.status = "MANUAL"
                report.status_extended = f"Subscription '{subscription}': this check is subscription-scoped and cannot be evaluated when --azure-resource-group is active. Re-run without --azure-resource-group to get full results."
                findings.append(report)
            return findings
        for subscription, pricings in defender_client.pricings.items():
            if "VirtualMachines" in pricings:
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource=pricings["VirtualMachines"],
                )
                report.subscription = subscription
                report.resource_name = "Defender plan Servers"
                report.status = "PASS"
                report.status_extended = f"Defender plan Defender for Servers from subscription {subscription} is set to ON (pricing tier standard)."
                if pricings["VirtualMachines"].pricing_tier != "Standard":
                    report.status = "FAIL"
                    report.status_extended = f"Defender plan Defender for Servers from subscription {subscription} is set to OFF (pricing tier not standard)."

                findings.append(report)
        return findings

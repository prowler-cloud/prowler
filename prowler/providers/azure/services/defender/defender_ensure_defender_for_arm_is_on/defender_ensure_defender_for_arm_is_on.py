from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_defender_for_arm_is_on(Check):
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
            subscription_name = defender_client.subscriptions.get(
                subscription, subscription
            )
            if "Arm" in pricings:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=pricings["Arm"]
                )
                report.subscription = subscription
                report.resource_name = "Defender plan ARM"
                report.status = "PASS"
                report.status_extended = f"Defender plan Defender for ARM from subscription {subscription_name} ({subscription}) is set to ON (pricing tier standard)."
                if pricings["Arm"].pricing_tier != "Standard":
                    report.status = "FAIL"
                    report.status_extended = f"Defender plan Defender for ARM from subscription {subscription_name} ({subscription}) is set to OFF (pricing tier not standard)."

                findings.append(report)
        return findings

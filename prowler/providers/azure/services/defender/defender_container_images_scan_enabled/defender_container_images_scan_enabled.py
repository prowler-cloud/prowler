from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_container_images_scan_enabled(Check):
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
            if "Containers" in pricings:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=pricings["Containers"]
                )
                report.subscription = subscription
                report.status = "PASS"
                report.status_extended = (
                    f"Container image scan is enabled in subscription {subscription}."
                )
                if not pricings["Containers"].extensions.get(
                    "ContainerRegistriesVulnerabilityAssessments"
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Container image scan is disabled in subscription {subscription}."

                findings.append(report)
        return findings

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.appinsights.appinsights_client import (
    appinsights_client,
)


class appinsights_ensure_is_configured(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, components in appinsights_client.components.items():
            if not components:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_name
                report.resource_name = subscription_name
                report.resource_id = f"/subscriptions/{appinsights_client.subscriptions[subscription_name]}"
                report.status = "FAIL"
                report.status_extended = f"There are no AppInsights configured in subscription {subscription_name}."
                findings.append(report)
            else:
                for component in components:
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=component
                    )
                    report.subscription = subscription_name
                    report.status = "PASS"
                    report.status_extended = f"AppInsight {component.name} is configured in subscription {subscription_name}."
                    findings.append(report)

        return findings

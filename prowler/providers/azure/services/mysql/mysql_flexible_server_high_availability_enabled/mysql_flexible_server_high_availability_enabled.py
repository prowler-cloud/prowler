from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.mysql.mysql_client import mysql_client


class mysql_flexible_server_high_availability_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, items in mysql_client.flexible_servers.items():
            for item_id, resource in items.items():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=resource
                )
                report.subscription = subscription_name
                report.resource_name = resource.name
                report.resource_id = resource.resource_id
                report.location = resource.location

                if resource.high_availability_mode is not None and resource.high_availability_mode != "Disabled":
                    report.status = "PASS"
                    report.status_extended = (
                        f"{resource.name} has high availability enabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"{resource.name} does not have high availability enabled."
                    )

                findings.append(report)

        return findings

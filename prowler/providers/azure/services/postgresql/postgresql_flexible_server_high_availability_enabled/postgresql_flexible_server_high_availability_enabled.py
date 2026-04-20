from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.postgresql.postgresql_client import postgresql_client


class postgresql_flexible_server_high_availability_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, items in postgresql_client.flexible_servers.items():
            for resource in items:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=resource
                )
                report.subscription = subscription_name
                report.resource_name = resource.name
                report.resource_id = resource.id
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

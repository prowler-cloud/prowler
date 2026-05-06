from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.mysql.mysql_client import mysql_client


class mysql_flexible_server_geo_redundant_backup_enabled(Check):
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

                if resource.geo_redundant_backup == "Enabled":
                    report.status = "PASS"
                    report.status_extended = (
                        f"{resource.name} has geo-redundant backup enabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"{resource.name} does not have geo-redundant backup enabled."
                    )

                findings.append(report)

        return findings

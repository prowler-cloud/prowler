from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.postgresql.postgresql_client import (
    postgresql_client,
)


class postgresql_flexible_server_allow_access_services_disabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for (
            subscription,
            flexible_servers,
        ) in postgresql_client.flexible_servers.items():
            for server in flexible_servers:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = server.name
                report.resource_id = server.id
                report.status = "FAIL"
                report.location = server.location
                report.status_extended = f"Flexible Postgresql server {server.name} from subscription {subscription} has allow public access from any Azure service enabled"
                if not any(
                    rule.start_ip == "0.0.0.0" and rule.end_ip == "0.0.0.0"
                    for rule in server.firewall
                ):
                    report.status = "PASS"
                    report.status_extended = f"Flexible Postgresql server {server.name} from subscription {subscription} has allow public access from any Azure service disabled"
                findings.append(report)

        return findings

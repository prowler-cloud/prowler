from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.postgresql.postgresql_client import (
    postgresql_client,
)


class postgresql_flexible_server_enforce_ssl_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for (
            subscription,
            flexible_servers,
        ) in postgresql_client.flexible_servers.items():
            print(flexible_servers)
            for server in flexible_servers:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = server.name
                report.resource_id = server.id
                report.status = "FAIL"
                report.status_extended = f"Flexible Postgresql server {server.name} from subscription {subscription} has enforce ssl disabled"
                if server.require_secure_transport == "ON":
                    report.status = "PASS"
                    report.status_extended = f"Flexible Postgresql server {server.name} from subscription {subscription} has enforce ssl enabled"
                findings.append(report)

        return findings

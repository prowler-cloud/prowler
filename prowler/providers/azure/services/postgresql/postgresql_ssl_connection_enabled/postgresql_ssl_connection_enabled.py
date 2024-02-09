from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.postgresql.postgresql_client import (
    postgresql_client,
)


class postgresql_ssl_connection_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, sql_servers in postgresql_client.postgresql_servers.items():
            for postgresql_servers in sql_servers:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = postgresql_servers.name
                report.resource_id = postgresql_servers.id
                report.status = "FAIL"

                findings.append(report)

        return findings

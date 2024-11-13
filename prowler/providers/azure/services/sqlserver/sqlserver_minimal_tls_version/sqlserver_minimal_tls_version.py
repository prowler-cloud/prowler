from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.sqlserver.sqlserver_client import sqlserver_client


class sqlserver_minimal_tls_version(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, sql_servers in sqlserver_client.sql_servers.items():
            for sql_server in sql_servers:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = sql_server.name
                report.resource_id = sql_server.id
                report.status = "FAIL"
                report.location = sql_server.location
                report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has no or an deprecated minimal TLS version set."
                if sql_server.minimal_tls_version in ("1.2", "1.3"):
                    report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has a recommended TLS version set."
                    report.status = "PASS"
                findings.append(report)

        return findings

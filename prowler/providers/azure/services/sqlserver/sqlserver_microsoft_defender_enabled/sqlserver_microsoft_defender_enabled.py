from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.sqlserver.sqlserver_client import sqlserver_client


class sqlserver_microsoft_defender_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, sql_servers in sqlserver_client.sql_servers.items():
            for sql_server in sql_servers:
                if sql_server.security_alert_policies:
                    report = Check_Report_Azure(self.metadata())
                    report.subscription = subscription
                    report.resource_name = sql_server.name
                    report.resource_id = sql_server.id
                    report.status = "FAIL"
                    report.location = sql_server.location
                    report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has microsoft defender disabled."
                    if sql_server.security_alert_policies.state == "Enabled":
                        report.status = "PASS"
                        report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has microsoft defender enabled."
                    findings.append(report)

        return findings

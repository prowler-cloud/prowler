from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.sqlserver.sqlserver_client import sqlserver_client


class sqlserver_va_periodic_recurring_scans_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, sql_servers in sqlserver_client.sql_servers.items():
            for sql_server in sql_servers:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = sql_server.name
                report.resource_id = sql_server.id
                report.status = "FAIL"
                report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has vulnerability assessment disabled."
                if (
                    sql_server.vulnerability_assessment
                    and sql_server.vulnerability_assessment.storage_container_path
                ):
                    report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has vulnerability assessment enabled but no recurring scans."
                    if (
                        sql_server.vulnerability_assessment.recurring_scans
                        and sql_server.vulnerability_assessment.recurring_scans.is_enabled
                    ):
                        report.status = "PASS"
                        report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has periodic recurring scans enabled."
                findings.append(report)

        return findings

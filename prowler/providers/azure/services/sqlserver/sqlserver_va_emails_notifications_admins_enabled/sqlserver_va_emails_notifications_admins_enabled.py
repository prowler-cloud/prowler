from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.sqlserver.sqlserver_client import sqlserver_client


class sqlserver_va_emails_notifications_admins_enabled(Check):
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
                report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has vulnerability assessment disabled."
                if (
                    sql_server.vulnerability_assessment
                    and sql_server.vulnerability_assessment.storage_container_path
                ):
                    report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has vulnerability assessment enabled but no scan reports configured for subscription admins."
                    if (
                        sql_server.vulnerability_assessment.recurring_scans
                        and sql_server.vulnerability_assessment.recurring_scans.email_subscription_admins
                    ):
                        report.status = "PASS"
                        report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has vulnerability assessment enabled and scan reports configured for subscription admins."
                findings.append(report)

        return findings

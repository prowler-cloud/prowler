from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.sqlserver.sqlserver_client import (
    sqlserver_client,
)


class sqlserver_advanced_data_security_enabled(Check):
    """Check if Advanced Data Security is enabled for Azure SQL Servers."""

    def execute(self) -> list[Check_Report_Azure]:
        """Execute the SQL Server Advanced Data Security check."""
        findings = []
        for subscription, sql_servers in sqlserver_client.sql_servers.items():
            subscription_name = sqlserver_client.subscriptions.get(
                subscription, subscription
            )
            for sql_server in sql_servers:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=sql_server
                )
                report.subscription = subscription
                report.status = "FAIL"
                report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription_name} ({subscription}) does not have Advanced Data Security enabled."

                if (
                    sql_server.security_alert_policies
                    and sql_server.security_alert_policies.state == "Enabled"
                ):
                    report.status = "PASS"
                    report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription_name} ({subscription}) has Advanced Data Security enabled."

                findings.append(report)

        return findings

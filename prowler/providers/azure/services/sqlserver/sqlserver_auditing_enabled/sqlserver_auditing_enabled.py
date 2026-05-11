from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.sqlserver.sqlserver_client import sqlserver_client


class sqlserver_auditing_enabled(Check):
    def execute(self) -> Check_Report_Azure:
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
                report.status = "PASS"
                report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription_name} ({subscription}) has an auditing policy configured."
                for auditing_policy in sql_server.auditing_policies:
                    if auditing_policy.state == "Disabled":
                        report.status = "FAIL"
                        report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription_name} ({subscription}) does not have any auditing policy configured."
                        break

                findings.append(report)

        return findings

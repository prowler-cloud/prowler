from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.sqlserver.sqlserver_client import sqlserver_client


class sqlserver_auditing_retention_90_days(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, sql_servers in sqlserver_client.sql_servers.items():
            for sql_server in sql_servers:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = sql_server.name
                report.resource_id = sql_server.id
                has_failed = False
                has_policy = False
                for policy in sql_server.auditing_policies:
                    has_policy = True
                    if has_failed:
                        break
                    if policy.state == "Enabled":
                        if policy.retention_days <= 90:
                            report.status = "FAIL"
                            report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has auditing retention less than 91 days."
                            has_failed = True
                        else:
                            report.status = "PASS"
                            report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has auditing retention greater than 90 days."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has auditing disabled."
                        has_failed = True
                if has_policy:
                    findings.append(report)

        return findings

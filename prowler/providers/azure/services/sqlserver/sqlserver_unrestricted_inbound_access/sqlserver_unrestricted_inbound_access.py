from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.sqlserver.sqlserver_client import sqlserver_client


class sqlserver_unrestricted_inbound_access(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, sql_servers in sqlserver_client.sql_servers.items():
            for sql_server in sql_servers:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.status = "PASS"
                report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} does not have firewall rules allowing 0.0.0.0-255.255.255.255."
                report.resource_name = sql_server.name
                report.resource_id = sql_server.id

                for firewall_rule in sql_server.firewall_rules:
                    if (
                        firewall_rule.start_ip_address == "0.0.0.0"
                        and firewall_rule.end_ip_address == "255.255.255.255"
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has firewall rules allowing 0.0.0.0-255.255.255.255."
                        break

                findings.append(report)

        return findings

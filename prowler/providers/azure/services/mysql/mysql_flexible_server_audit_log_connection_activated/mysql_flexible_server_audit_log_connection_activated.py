from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.mysql.mysql_client import mysql_client


class mysql_flexible_server_audit_log_connection_activated(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            servers,
        ) in mysql_client.flexible_servers.items():
            for (
                server_name,
                server,
            ) in servers.items():

                    report = Check_Report_Azure(self.metadata())
                    report.status = "PASS"
                    report.subscription = subscription_name
                    report.resource_name = server_name
                    report.resource_id = server.configurations[
                        "audit_log_events"
                    ].resource_id
                    report.status_extended = f"Audit log is enabled for server {server_name} in subscription {subscription_name}."

                    if "audit_log_events" not in server.configurations or "CONNECTION" not in server.configurations[
                        "audit_log_events"
                    ].value.split(","):
                        report.status = "FAIL"
                        report.status_extended = f"Audit log is disabled for server {server_name} in subscription {subscription_name}."

                    findings.append(report)

        return findings

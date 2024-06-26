from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.mysql.mysql_client import mysql_client


class mysql_flexible_server_ssl_connection_enabled(Check):
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
                report.status = "FAIL"
                report.subscription = subscription_name
                report.resource_name = server_name
                report.resource_id = server_name
                report.location = server.location
                report.status_extended = f"SSL connection is disabled for server {server_name} in subscription {subscription_name}."

                if "require_secure_transport" in server.configurations:
                    report.resource_id = server.configurations[
                        "require_secure_transport"
                    ].resource_id
                    if server.configurations["require_secure_transport"].value == "ON":
                        report.status = "PASS"
                        report.status_extended = f"SSL connection is enabled for server {server_name} in subscription {subscription_name}."

                findings.append(report)

        return findings

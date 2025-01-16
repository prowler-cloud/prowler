from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.mysql.mysql_client import mysql_client


class mysql_flexible_server_ssl_connection_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            servers,
        ) in mysql_client.flexible_servers.items():
            for server in servers.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource_metadata=server
                )
                report.subscription = subscription_name
                report.status = "FAIL"
                report.status_extended = f"SSL connection is disabled for server {server.name} in subscription {subscription_name}."

                if "require_secure_transport" in server.configurations:
                    report.resource_id = server.configurations[
                        "require_secure_transport"
                    ].resource_id
                    if server.configurations["require_secure_transport"].value == "ON":
                        report.status = "PASS"
                        report.status_extended = f"SSL connection is enabled for server {server.name} in subscription {subscription_name}."

                findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.mysql.mysql_client import mysql_client


class mysql_flexible_server_minimum_tls_version_12(Check):
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
                report.status_extended = f"TLS version is not configured in server {server_name} in subscription {subscription_name}."

                if "tls_version" in server.configurations:
                    report.status = "PASS"
                    report.resource_id = server.configurations[
                        "tls_version"
                    ].resource_id
                    report.status_extended = f"TLS version is {server.configurations['tls_version'].value} in server {server_name} in subscription {subscription_name}. This version of TLS is considered secure."

                    tls_aviable = server.configurations["tls_version"].value.split(",")

                    if "TLSv1.0" in tls_aviable or "TLSv1.1" in tls_aviable:
                        report.status = "FAIL"
                        report.status_extended = f"TLS version is {server.configurations['tls_version'].value} in server {server_name} in subscription {subscription_name}. There is at leat one version of TLS that is considered insecure."

                findings.append(report)

        return findings

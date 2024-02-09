from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.mysql.mysql_client import mysql_client


class mysql_tls_version_is_1_2(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            servers,
        ) in mysql_client.servers.items():
            for (
                server_name,
                server,
            ) in servers.items():

                if "tls_version" in server.configurations:
                    report = Check_Report_Azure(self.metadata())
                    report.status = "PASS"
                    report.subscription = subscription_name
                    report.resource_name = server_name
                    report.resource_id = server.resource_id
                    report.status_extended = f"TLS version is {server.configurations['tls_version'].value} in server {server_name} in subscription {subscription_name}. This version of TLS is considered secure."

                    if (
                        server.configurations["tls_version"].value.find("TLSv1.2") == -1
                        and server.configurations["tls_version"].value.find("TLSv1.3")
                        == -1
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"TLS version is {server.configurations['tls_version'].value} in server {server_name} in subscription {subscription_name}. This version of TLS is considered insecure."

                    findings.append(report)

        return findings

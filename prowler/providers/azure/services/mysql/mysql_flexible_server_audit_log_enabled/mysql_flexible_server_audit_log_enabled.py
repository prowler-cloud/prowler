from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.mysql.mysql_client import mysql_client


class mysql_flexible_server_audit_log_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_id,
            servers,
        ) in mysql_client.flexible_servers.items():
            for server in servers.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=server)
                report.status = "FAIL"
                report.subscription = subscription_id
                report.status_extended = f"Audit log is disabled for server {server.name} in subscription {subscription_id}."

                if "audit_log_enabled" in server.configurations:
                    report.resource_id = server.configurations[
                        "audit_log_enabled"
                    ].resource_id

                    if server.configurations["audit_log_enabled"].value.lower() == "on":
                        report.status = "PASS"
                        report.status_extended = f"Audit log is enabled for server {server.name} in subscription {subscription_id}."

                findings.append(report)

        return findings

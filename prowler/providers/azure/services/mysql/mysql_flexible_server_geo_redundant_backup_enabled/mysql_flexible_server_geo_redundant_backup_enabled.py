from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.mysql.mysql_client import mysql_client


class mysql_flexible_server_geo_redundant_backup_enabled(Check):
    """
    Ensure Azure MySQL Flexible Servers have geo-redundant backup enabled.

    This check evaluates whether each Azure MySQL Flexible Server stores backups in a paired Azure region, enabling recovery from a full regional outage.

    - PASS: The server has geo-redundant backup enabled (geo_redundant_backup is "Enabled").
    - FAIL: The server does not have geo-redundant backup enabled.
    """

    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription_id, servers in mysql_client.flexible_servers.items():
            subscription_name = mysql_client.subscriptions.get(
                subscription_id, subscription_id
            )
            for server in servers.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=server)
                report.subscription = subscription_id
                if server.geo_redundant_backup == "Enabled":
                    report.status = "PASS"
                    report.status_extended = f"Geo-redundant backup is enabled for server {server.name} in subscription {subscription_name} ({subscription_id})."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Geo-redundant backup is disabled for server {server.name} in subscription {subscription_name} ({subscription_id})."
                findings.append(report)
        return findings

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.mysql.mysql_client import mysql_client


class mysql_flexible_server_high_availability_enabled(Check):
    """
    Ensure Azure MySQL Flexible Servers have high availability enabled.

    This check evaluates whether each Azure MySQL Flexible Server is configured with high availability (zone-redundant or same-zone), providing automatic failover to a standby replica during outages.

    - PASS: The server has high availability enabled (high_availability_mode is set and not "Disabled").
    - FAIL: The server does not have high availability enabled.
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
                if (
                    server.high_availability_mode is not None
                    and server.high_availability_mode != "Disabled"
                ):
                    report.status = "PASS"
                    report.status_extended = f"High availability is enabled for server {server.name} in subscription {subscription_name} ({subscription_id})."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"High availability is disabled for server {server.name} in subscription {subscription_name} ({subscription_id})."
                findings.append(report)
        return findings

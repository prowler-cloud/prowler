from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.postgresql.postgresql_client import (
    postgresql_client,
)


class postgresql_flexible_server_high_availability_enabled(Check):
    """
    Ensure Azure PostgreSQL Flexible Servers have high availability enabled.

    This check evaluates whether each Azure PostgreSQL Flexible Server is configured with high availability (zone-redundant or same-zone), providing automatic failover to a standby replica during outages.

    - PASS: The server has high availability enabled (high_availability_mode is set and not "Disabled").
    - FAIL: The server does not have high availability enabled.
    """

    def execute(self) -> Check_Report_Azure:
        findings = []
        for (
            subscription,
            flexible_servers,
        ) in postgresql_client.flexible_servers.items():
            subscription_name = postgresql_client.subscriptions.get(
                subscription, subscription
            )
            for server in flexible_servers:
                report = Check_Report_Azure(metadata=self.metadata(), resource=server)
                report.subscription = subscription
                if (
                    server.high_availability_mode is not None
                    and server.high_availability_mode != "Disabled"
                ):
                    report.status = "PASS"
                    report.status_extended = f"Flexible Postgresql server {server.name} from subscription {subscription_name} ({subscription}) has high availability enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Flexible Postgresql server {server.name} from subscription {subscription_name} ({subscription}) does not have high availability enabled."
                findings.append(report)
        return findings

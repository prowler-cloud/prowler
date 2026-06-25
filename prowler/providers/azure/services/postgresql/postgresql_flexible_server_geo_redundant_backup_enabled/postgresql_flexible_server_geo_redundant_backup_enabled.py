from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.postgresql.postgresql_client import (
    postgresql_client,
)


class postgresql_flexible_server_geo_redundant_backup_enabled(Check):
    """
    Ensure Azure PostgreSQL Flexible Servers have geo-redundant backup enabled.

    This check evaluates whether each Azure PostgreSQL Flexible Server stores backups in a paired Azure region, enabling cross-region disaster recovery.

    - PASS: The server has geo-redundant backup enabled (geo_redundant_backup is "Enabled").
    - FAIL: The server does not have geo-redundant backup enabled.
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
                if server.geo_redundant_backup == "Enabled":
                    report.status = "PASS"
                    report.status_extended = f"Flexible Postgresql server {server.name} from subscription {subscription_name} ({subscription}) has geo-redundant backup enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Flexible Postgresql server {server.name} from subscription {subscription_name} ({subscription}) does not have geo-redundant backup enabled."
                findings.append(report)
        return findings

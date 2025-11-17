from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.postgresql.postgresql_client import (
    postgresql_client,
)


class postgresql_flexible_server_entra_id_authentication_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for (
            subscription,
            flexible_servers,
        ) in postgresql_client.flexible_servers.items():
            for server in flexible_servers:
                report = Check_Report_Azure(metadata=self.metadata(), resource=server)
                report.subscription = subscription
                # Default to FAIL
                report.status = "FAIL"

                # Check if Entra ID authentication is enabled
                # Note: active_directory_auth is already normalized to uppercase in service layer
                if (
                    not server.active_directory_auth
                    or server.active_directory_auth != "ENABLED"
                ):
                    report.status_extended = f"Flexible Postgresql server {server.name} from subscription {subscription} has Microsoft Entra ID authentication disabled"
                else:
                    # Authentication is enabled, now check for admins
                    admin_count = (
                        len(server.entra_id_admins) if server.entra_id_admins else 0
                    )

                    if admin_count == 0:
                        report.status_extended = f"Flexible Postgresql server {server.name} from subscription {subscription} has Microsoft Entra ID authentication enabled but no Entra ID administrators configured"
                    else:
                        report.status = "PASS"
                        admin_text = (
                            "administrator" if admin_count == 1 else "administrators"
                        )
                        report.status_extended = f"Flexible Postgresql server {server.name} from subscription {subscription} has Microsoft Entra ID authentication enabled with {admin_count} {admin_text} configured"
                findings.append(report)

        return findings

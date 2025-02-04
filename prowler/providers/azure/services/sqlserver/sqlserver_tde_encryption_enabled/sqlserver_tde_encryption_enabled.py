from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.sqlserver.sqlserver_client import sqlserver_client


class sqlserver_tde_encryption_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, sql_servers in sqlserver_client.sql_servers.items():
            for sql_server in sql_servers:
                databases = (
                    sql_server.databases if sql_server.databases is not None else []
                )
                if len(databases) > 0:
                    for database in databases:
                        if database.name.lower() == "master":
                            continue
                        report = Check_Report_Azure(
                            metadata=self.metadata(), resource=database
                        )
                        report.subscription = subscription
                        if database.tde_encryption.status == "Enabled":
                            report.status = "PASS"
                            report.status_extended = f"Database {database.name} from SQL Server {sql_server.name} from subscription {subscription} has TDE enabled"
                        else:
                            report.status = "FAIL"
                            report.status_extended = f"Database {database.name} from SQL Server {sql_server.name} from subscription {subscription} has TDE disabled"
                        findings.append(report)

        return findings

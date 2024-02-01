from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.sqlserver.sqlserver_client import sqlserver_client


class sqlserver_tde_encrypted_with_cmk(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, sql_servers in sqlserver_client.sql_servers.items():
            for sql_server in sql_servers:
                databases = (
                    sql_server.databases if sql_server.databases is not None else []
                )
                if len(databases) > 0:
                    report = Check_Report_Azure(self.metadata())
                    report.subscription = subscription
                    report.resource_name = sql_server.name
                    report.resource_id = sql_server.id
                    found_disabled = False
                    if (
                        sql_server.encryption_protector.server_key_type
                        == "AzureKeyVault"
                    ):
                        for database in databases:
                            if found_disabled:
                                break
                            if database.tde_encryption.status == "Enabled":
                                report.status = "PASS"
                                report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has TDE enabled with CMK."
                            else:
                                report.status = "FAIL"
                                report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has TDE disabled with CMK."
                                found_disabled = True
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} has TDE disabled without CMK."
                    findings.append(report)

        return findings

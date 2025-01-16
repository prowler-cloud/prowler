from typing import List

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.sqlserver.sqlserver_client import sqlserver_client


class sqlserver_recommended_minimal_tls_version(Check):
    def execute(self) -> List[Check_Report_Azure]:
        findings = []
        recommended_minimal_tls_versions = sqlserver_client.audit_config.get(
            "recommended_minimal_tls_versions", ["1.2", "1.3"]
        )
        for subscription, sql_servers in sqlserver_client.sql_servers.items():
            for sql_server in sql_servers:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource_metadata=sql_server
                )
                report.subscription = subscription
                report.status = "FAIL"
                report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} is using TLS version {sql_server.minimal_tls_version} as minimal accepted which is not recommended. Please use one of the recommended versions: {', '.join(recommended_minimal_tls_versions)}."
                if sql_server.minimal_tls_version in recommended_minimal_tls_versions:
                    report.status_extended = f"SQL Server {sql_server.name} from subscription {subscription} is using version {sql_server.minimal_tls_version} as minimal accepted which is recommended."
                    report.status = "PASS"
                findings.append(report)

        return findings

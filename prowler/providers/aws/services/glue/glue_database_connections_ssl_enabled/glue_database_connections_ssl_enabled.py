from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.glue.glue_client import glue_client


class glue_database_connections_ssl_enabled(Check):
    def execute(self):
        findings = []
        for conn in glue_client.connections:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = conn.name
            report.region = conn.region
            report.status = "FAIL"
            report.status_extended = (
                f"Glue connection {conn.name} has SSL connection disabled."
            )
            if conn.properties.get("JDBC_ENFORCE_SSL") == "true":
                report.status = "PASS"
                report.status_extended = (
                    f"Glue connection {conn.name} has SSL connection enabled."
                )
            findings.append(report)
        return findings

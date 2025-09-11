from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_postgres_log_min_duration_statement_flag(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in cloudsql_client.instances:
            if "POSTGRES" in instance.version:
                report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
                report.status = "PASS"
                report.status_extended = f"PostgreSQL Instance {instance.name} has 'log_min_duration_statement' flag set to '-1'."
                for flag in instance.flags:
                    if (
                        flag.get("name", "") == "log_min_duration_statement"
                        and flag.get("value", "-1") != "-1"
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"PostgreSQL Instance {instance.name} does not have 'log_min_duration_statement' flag set to '-1'."
                        break
                findings.append(report)

        return findings

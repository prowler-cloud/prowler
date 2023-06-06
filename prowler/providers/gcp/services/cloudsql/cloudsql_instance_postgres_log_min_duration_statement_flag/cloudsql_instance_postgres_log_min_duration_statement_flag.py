from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_postgres_log_min_duration_statement_flag(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in cloudsql_client.instances:
            if "POSTGRES" in instance.version:
                report = Check_Report_GCP(self.metadata())
                report.project_id = instance.project_id
                report.resource_id = instance.name
                report.resource_name = instance.name
                report.location = instance.region
                report.status = "FAIL"
                report.status_extended = f"PostgreSQL Instance {instance.name} has not 'log_min_duration_statement' flag set to '-1'"
                for flag in instance.flags:
                    if (
                        flag["name"] == "log_min_duration_statement"
                        and flag["value"] == "-1"
                    ):
                        report.status = "PASS"
                        report.status_extended = f"PostgreSQL Instance {instance.name} has 'log_min_duration_statement' flag set to '-1'"
                        break
                findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_postgres_log_error_verbosity_flag(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in cloudsql_client.instances:
            if "POSTGRES" in instance.version:
                report = Check_Report_GCP(self.metadata())
                report.project_id = instance.project_id
                report.resource_id = instance.name
                report.resource_name = instance.name
                report.location = instance.region
                report.status = "PASS"
                report.status_extended = f"PostgreSQL Instance {instance.name} has 'log_error_verbosity' flag set to 'default'."
                for flag in instance.flags:
                    if (
                        flag.get("name", "") == "log_error_verbosity"
                        and flag.get("value", "default") != "default"
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"PostgreSQL Instance {instance.name} does not have 'log_error_verbosity' flag set to 'default'."
                        break
                findings.append(report)

        return findings

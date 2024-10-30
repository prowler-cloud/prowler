from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_postgres_log_min_messages_flag(Check):
    def execute(self) -> Check_Report_GCP:
        failing_log_levels = [
            "DEBUG5",
            "DEBUG4",
            "DEBUG3",
            "DEBUG2",
            "DEBUG1",
            "INFO",
            "NOTICE",
        ]

        findings = []
        for instance in cloudsql_client.instances:
            if "POSTGRES" in instance.version:
                report = Check_Report_GCP(self.metadata())
                report.project_id = instance.project_id
                report.resource_id = instance.name
                report.resource_name = instance.name
                report.location = instance.region
                report.status = "FAIL"
                report.status_extended = f"PostgreSQL Instance {instance.name} does not have 'log_min_messages' flag set."

                for flag in instance.flags:
                    if flag.get("name", "") == "log_min_messages":
                        current_level = flag.get("value", "").upper()
                        if current_level in failing_log_levels:
                            report.status = "FAIL"
                            report.status_extended = f"PostgreSQL Instance {instance.name} has 'log_min_messages' flag set to '{current_level}', which is below the recommended minimum of 'ERROR'."
                        else:
                            report.status = "PASS"
                            report.status_extended = f"PostgreSQL Instance {instance.name} has 'log_min_messages' flag set to an acceptable severity level: '{current_level}'."
                findings.append(report)

        return findings

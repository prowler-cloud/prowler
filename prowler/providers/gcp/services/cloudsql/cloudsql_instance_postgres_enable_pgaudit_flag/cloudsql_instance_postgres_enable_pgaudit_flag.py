from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_postgres_enable_pgaudit_flag(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in cloudsql_client.instances:
            if "POSTGRES" in instance.version:
                report = Check_Report_GCP(
                    metadata=self.metadata(), resource_metadata=instance
                )
                report.status = "FAIL"
                report.status_extended = f"PostgreSQL Instance {instance.name} does not have 'cloudsql.enable_pgaudit' flag set to 'on'."
                for flag in instance.flags:
                    if (
                        flag.get("name", "") == "cloudsql.enable_pgaudit"
                        and flag.get("value", "off") == "on"
                    ):
                        report.status = "PASS"
                        report.status_extended = f"PostgreSQL Instance {instance.name} has 'cloudsql.enable_pgaudit' flag set to 'on'."
                        break
                findings.append(report)

        return findings

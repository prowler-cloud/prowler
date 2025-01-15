from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_sqlserver_contained_database_authentication_flag(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in cloudsql_client.instances:
            if "SQLSERVER" in instance.version:
                report = Check_Report_GCP(
                    metadata=self.metadata(), resource_metadata=instance
                )
                report.status = "PASS"
                report.status_extended = f"SQL Server Instance {instance.name} has 'contained database authentication' flag set to 'off'."
                for flag in instance.flags:
                    if (
                        flag.get("name", "") == "contained database authentication"
                        and flag.get("value", "off") == "on"
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"SQL Server Instance {instance.name} has 'contained database authentication' flag set to 'on'."
                        break
                findings.append(report)

        return findings

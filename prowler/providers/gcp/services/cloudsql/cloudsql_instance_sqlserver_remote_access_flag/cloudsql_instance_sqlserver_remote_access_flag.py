from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_sqlserver_remote_access_flag(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in cloudsql_client.instances:
            if "SQLSERVER" in instance.version:
                report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
                report.status = "FAIL"
                report.status_extended = f"SQL Server Instance {instance.name} has 'remote access' flag set to 'on'."
                for flag in instance.flags:
                    if (
                        flag.get("name", "") == "remote access"
                        and flag.get("value", "on") != "on"
                    ):
                        report.status = "PASS"
                        report.status_extended = f"SQL Server Instance {instance.name} does not have 'remote access' flag set to 'on'."
                        break
                findings.append(report)

        return findings

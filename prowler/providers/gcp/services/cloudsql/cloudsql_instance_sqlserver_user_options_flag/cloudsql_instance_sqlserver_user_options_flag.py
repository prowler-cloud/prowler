from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_sqlserver_user_options_flag(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in cloudsql_client.instances:
            if "SQLSERVER" in instance.version:
                report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
                report.status = "PASS"
                report.status_extended = f"SQL Server Instance {instance.name} does not have 'user options' flag set."
                for flag in instance.flags:
                    if (
                        flag.get("name", "") == "user options"
                        and flag.get("value", "") != ""
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"SQL Server Instance {instance.name} has 'user options' flag set."
                        break
                findings.append(report)

        return findings

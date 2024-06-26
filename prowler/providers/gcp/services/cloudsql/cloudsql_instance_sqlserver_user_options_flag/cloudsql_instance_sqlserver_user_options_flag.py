from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_sqlserver_user_options_flag(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in cloudsql_client.instances:
            if "SQLSERVER" in instance.version:
                report = Check_Report_GCP(self.metadata())
                report.project_id = instance.project_id
                report.resource_id = instance.name
                report.resource_name = instance.name
                report.location = instance.region
                report.status = "PASS"
                report.status_extended = f"SQL Server Instance {instance.name} does not have 'user options' flag set."
                for flag in instance.flags:
                    if flag["name"] == "user options" and flag["value"] != "":
                        report.status = "FAIL"
                        report.status_extended = f"SQL Server Instance {instance.name} has 'user options' flag set."
                        break
                findings.append(report)

        return findings

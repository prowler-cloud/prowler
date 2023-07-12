from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_sqlserver_remote_access_flag(Check):
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
                report.status_extended = f"SQL Server Instance {instance.name} has not 'remote access' flag set to 'on'"
                for flag in instance.flags:
                    if flag["name"] == "remote access" and flag["value"] == "on":
                        report.status = "FAIL"
                        report.status_extended = f"SQL Server Instance {instance.name} has 'remote access' flag set to 'on'"
                        break
                findings.append(report)

        return findings

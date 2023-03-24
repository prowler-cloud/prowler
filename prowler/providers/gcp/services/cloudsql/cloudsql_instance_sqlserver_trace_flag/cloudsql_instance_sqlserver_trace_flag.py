from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_sqlserver_trace_flag(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in cloudsql_client.instances:
            if "SQLSERVER" in instance.version:
                report = Check_Report_GCP(self.metadata())
                report.project_id = cloudsql_client.project_id
                report.resource_id = instance.name
                report.resource_name = instance.name
                report.location = instance.region
                report.status = "PASS"
                report.status_extended = f"SQL Server Instance {instance.name} has '3625 (trace flag)' flag set to 'on'"
                for flag in instance.flags:
                    if flag["name"] == "3625" and flag["value"] == "off":
                        report.status = "FAIL"
                        report.status_extended = f"SQL Server Instance {instance.name} has '3625 (trace flag)' flag set to 'off'"
                        break
                findings.append(report)

        return findings

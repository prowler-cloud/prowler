from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_mysql_local_infile_flag(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in cloudsql_client.instances:
            if "MYSQL" in instance.version:
                report = Check_Report_GCP(self.metadata())
                report.project_id = cloudsql_client.project_id
                report.resource_id = instance.name
                report.resource_name = instance.name
                report.location = instance.region
                report.status = "FAIL"
                report.status_extended = f"MySQL Instance {instance.name} has not 'local_infile' flag set to 'off'"
                for flag in instance.flags:
                    if flag["name"] == "local_infile" and flag["value"] == "off":
                        report.status = "PASS"
                        report.status_extended = f"MySQL Instance {instance.name} has 'local_infile' flag set to 'off'"
                        break
                findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudsql.cloudsql_client import cloudsql_client


class cloudsql_instance_public_ip(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in cloudsql_client.instances:
            report = Check_Report_GCP(self.metadata())
            report.project_id = cloudsql_client.project_id
            report.resource_id = instance.name
            report.resource_name = instance.name
            report.location = instance.region
            report.status = "PASS"
            report.status_extended = (
                f"Database Instance {instance.name} has not a public IP"
            )
            if instance.public_ip:
                report.status = "FAIL"
                report.status_extended = (
                    f"Database Instance {instance.name} has a public IP"
                )
            findings.append(report)

        return findings

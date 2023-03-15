from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.computeengine.computeengine_client import (
    computeengine_client,
)


class computeengine_instance_public_ip(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in computeengine_client.instances:
            report = Check_Report_GCP(self.metadata())
            report.project_id = computeengine_client.project_id
            report.resource_id = instance.id
            report.resource_name = instance.name
            report.region = instance.zone
            report.status = "PASS"
            report.status_extended = f"VM Instance {instance.name} has not a public IP"
            if instance.public_ip:
                report.status = "FAIL"
                report.status_extended = f"VM Instance {instance.name} has a public IP"
            findings.append(report)

        return findings

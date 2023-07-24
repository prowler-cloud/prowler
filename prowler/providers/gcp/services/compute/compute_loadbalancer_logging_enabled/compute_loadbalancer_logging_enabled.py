from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_loadbalancer_logging_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for lb in compute_client.load_balancers:
            report = Check_Report_GCP(self.metadata())
            report.project_id = lb.project_id
            report.resource_id = lb.id
            report.resource_name = lb.name
            report.location = compute_client.region
            report.status = "PASS"
            report.status_extended = f"LoadBalancer {lb.name} has logging enabled"
            if not lb.logging:
                report.status = "FAIL"
                report.status_extended = (
                    f"LoadBalancer {lb.name} does not have logging enabled"
                )
            findings.append(report)

        return findings

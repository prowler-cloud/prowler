from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wellarchitected.wellarchitected_client import (
    wellarchitected_client,
)


class wellarchitected_workload_no_high_or_medium_risks(Check):
    def execute(self):
        findings = []
        for workload in wellarchitected_client.workloads:
            report = Check_Report_AWS(self.metadata())
            report.region = workload.region
            report.resource_id = workload.id
            report.resource_arn = workload.arn
            report.resource_tags = workload.tags
            report.status = "PASS"
            report.status_extended = f"Well Architected workload {workload.name} does not contain high or medium risks."
            if "HIGH" in workload.risks or "MEDIUM" in workload.risks:
                report.status = "FAIL"
                report.status_extended = f"Well Architected workload {workload.name} contains {workload.risks.get('HIGH',0)} high and {workload.risks.get('MEDIUM',0)} medium risks."

            findings.append(report)
        return findings

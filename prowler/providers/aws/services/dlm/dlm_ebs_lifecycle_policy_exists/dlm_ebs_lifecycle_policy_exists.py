from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dlm.dlm_client import dlm_client


class dlm_ebs_lifecycle_policy_exists(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.status_extended = "No EBS lifecycle policies found."
        if len(dlm_client.lifecycle_policies) > 0:
            report.status = "PASS"
            report.status_extended = "EBS lifecycle policies found."
        findings.append(report)
        return findings

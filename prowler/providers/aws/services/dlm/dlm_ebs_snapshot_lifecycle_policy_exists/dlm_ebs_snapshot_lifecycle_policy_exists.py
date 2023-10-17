from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dlm.dlm_client import dlm_client


class dlm_ebs_snapshot_lifecycle_policy_exists(Check):
    def execute(self):
        findings = []
        for region in dlm_client.lifecycle_policies:
            report = Check_Report_AWS(self.metadata())
            report.status = "FAIL"
            report.status_extended = "No EBS Snapshot lifecycle policies found."
            report.region = region
            report.resource_id = dlm_client.audited_account
            report.resource_arn = dlm_client.audited_account_arn
            if dlm_client.lifecycle_policies[region]:
                report.status = "PASS"
                report.status_extended = "EBS snapshot lifecycle policies found."
            findings.append(report)
        return findings

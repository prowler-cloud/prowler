from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dlm.dlm_client import dlm_client
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class dlm_ebs_snapshot_lifecycle_policy_exists(Check):
    def execute(self):
        findings = []
        for region in dlm_client.lifecycle_policies:
            if (
                region in ec2_client.regions_with_snapshots
                and ec2_client.regions_with_snapshots[region]
            ):
                report = Check_Report_AWS(self.metadata())
                report.status = "FAIL"
                report.status_extended = "No EBS Snapshot lifecycle policies found."
                report.region = region
                report.resource_id = dlm_client.audited_account
                report.resource_arn = dlm_client.__get_lifecycle_policy_arn_template__(
                    region
                )
                if dlm_client.lifecycle_policies[region]:
                    report.status = "PASS"
                    report.status_extended = "EBS snapshot lifecycle policies found."
                findings.append(report)
        return findings

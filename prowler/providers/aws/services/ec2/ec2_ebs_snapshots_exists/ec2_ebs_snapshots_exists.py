from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ebs_snapshots_exists(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.status_extended = "EBS Snapshots don't exist."
        if len(ec2_client.snapshots) > 0:
            report.status = "PASS"
            report.status_extended = "EBS Snapshots exist."
        findings.append(report)
        return findings

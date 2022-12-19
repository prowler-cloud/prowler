from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ebs_snapshots_encrypted(Check):
    def execute(self):
        findings = []
        for snapshot in ec2_client.snapshots:
            report = Check_Report_AWS(self.metadata())
            report.region = snapshot.region
            if snapshot.encrypted:
                report.status = "PASS"
                report.status_extended = f"EBS Snapshot {snapshot.id} is encrypted."
                report.resource_id = snapshot.id
            else:
                report.status = "FAIL"
                report.status_extended = f"EBS Snapshot {snapshot.id} is unencrypted."
                report.resource_id = snapshot.id
            findings.append(report)

        return findings

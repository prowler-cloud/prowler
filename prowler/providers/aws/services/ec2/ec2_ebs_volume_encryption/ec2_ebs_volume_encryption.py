from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ebs_volume_encryption(Check):
    def execute(self):
        findings = []
        for volume in ec2_client.volumes:
            report = Check_Report_AWS(metadata=self.metadata(), resource=volume)
            report.status = "PASS"
            report.status_extended = f"EBS Snapshot {volume.id} is encrypted."
            if not volume.encrypted:
                report.status = "FAIL"
                report.status_extended = f"EBS Snapshot {volume.id} is unencrypted."
            findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ebs_volume_encryption(Check):
    def execute(self):
        findings = []
        for volume in ec2_client.volumes:
            report = Check_Report_AWS(self.metadata())
            report.region = volume.region
            report.resource_id = volume.id
            report.resource_arn = volume.arn
            if volume.encrypted:
                report.status = "PASS"
                report.status_extended = f"EBS Snapshot {volume.id} is encrypted."
            else:
                report.status = "FAIL"
                report.status_extended = f"EBS Snapshot {volume.id} is unencrypted."
            findings.append(report)

        return findings

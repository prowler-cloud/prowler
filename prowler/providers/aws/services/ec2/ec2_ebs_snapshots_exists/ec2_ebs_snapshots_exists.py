from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ebs_snapshots_exists(Check):
    def execute(self):
        findings = []
        for volume in ec2_client.volumes:
            report = Check_Report_AWS(self.metadata())
            report.status = "FAIL"
            report.region = volume.region
            report.resource_id = volume.id
            report.resource_arn = volume.arn
            report.resource_tags = volume.tags
            report.status_extended = f"Snapshots not found to EBS volume {volume.id}"
            if ec2_client.volumes_with_snapshots.get(volume.id, False):
                report.status = "PASS"
                report.status_extended = f"Snapshots found to EBS volume {volume.id}"
            findings.append(report)
        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.backup.backup_client import backup_client
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ebs_volume_protected_by_backup_plan(Check):
    def execute(self):
        findings = []
        for volume in ec2_client.volumes:
            report = Check_Report_AWS(self.metadata())
            report.region = volume.region
            report.resource_id = volume.id
            report.resource_arn = volume.arn
            report.resource_tags = volume.tags
            report.status = "FAIL"
            report.status_extended = (
                f"EBS Volume {volume.id} is not protected by a backup plan."
            )
            if (
                volume.arn in backup_client.protected_resources
                or f"arn:{ec2_client.audited_partition}:ec2:*:*:volume/*"
                in backup_client.protected_resources
                or "*" in backup_client.protected_resources
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"EBS Volume {volume.id} is protected by a backup plan."
                )

            findings.append(report)

        return findings

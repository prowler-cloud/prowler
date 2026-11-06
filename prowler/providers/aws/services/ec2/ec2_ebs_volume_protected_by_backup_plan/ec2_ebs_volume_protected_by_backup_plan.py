from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.backup.backup_client import backup_client
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ebs_volume_protected_by_backup_plan(Check):
    def execute(self):
        """Evaluate EBS volume coverage by AWS Backup selections.

        Apply selection-local exclusions before the existing inclusion rules.
        Selection coverage does not establish backup completion or restorability.

        Returns:
            A list of findings, one per collected EBS volume.
        """
        findings = []
        for volume in ec2_client.volumes:
            report = Check_Report_AWS(metadata=self.metadata(), resource=volume)
            report.status = "FAIL"
            report.status_extended = (
                f"EBS Volume {volume.id} is not protected by a backup plan."
            )
            protected_resources = backup_client.get_protected_resources(volume.arn)
            if (
                volume.arn in protected_resources
                or f"arn:{ec2_client.audited_partition}:ec2:*:*:volume/*"
                in protected_resources
                or "*" in protected_resources
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"EBS Volume {volume.id} is protected by a backup plan."
                )

            findings.append(report)

        return findings

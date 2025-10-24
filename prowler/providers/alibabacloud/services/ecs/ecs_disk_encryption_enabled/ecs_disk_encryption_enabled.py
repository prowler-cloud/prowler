from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ecs.ecs_client import ecs_client


class ecs_disk_encryption_enabled(Check):
    """
    Check if ECS disks are encrypted

    This check ensures that all ECS disks (both system and data disks) are
    encrypted to protect data at rest. Encryption helps prevent unauthorized
    access to disk data.

    Risk: Unencrypted disks can expose sensitive data if physical media is
    compromised or if snapshots are inadvertently shared.

    Recommendation: Enable disk encryption for all ECS disks using Alibaba
    Cloud KMS (Key Management Service).
    """

    def execute(self):
        """Execute the check"""
        findings = []

        # Iterate through all ECS disks
        for disk_arn, disk in ecs_client.disks.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=disk)
            report.account_uid = ecs_client.account_id
            report.region = disk.region
            report.resource_id = disk.id
            report.resource_arn = disk.arn

            if disk.encrypted:
                report.status = "PASS"
                report.status_extended = (
                    f"ECS disk {disk.name} ({disk.id}) is encrypted"
                )
                if disk.kms_key_id:
                    report.status_extended += f" using KMS key {disk.kms_key_id}"
                report.status_extended += "."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"ECS disk {disk.name} ({disk.id}) is not encrypted. "
                    f"Enable encryption to protect data at rest."
                )

            findings.append(report)

        return findings

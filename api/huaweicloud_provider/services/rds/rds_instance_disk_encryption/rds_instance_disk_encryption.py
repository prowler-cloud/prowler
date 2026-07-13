from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.rds.rds_client import rds_client


class rds_instance_disk_encryption(Check):
    """Ensure RDS instances have disk encryption enabled."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for instance in rds_client.instances:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(), resource=instance
            )
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = (
                f"huaweicloud:rds:{instance.region}:{rds_client.audited_account}:instance/{instance.id}"
            )

            if instance.disk_encryption_id:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS instance {instance.name} ({instance.id}) has disk encryption enabled "
                    f"with KMS key {instance.disk_encryption_id}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS instance {instance.name} ({instance.id}) does not have disk encryption enabled."
                )

            findings.append(report)

        return findings

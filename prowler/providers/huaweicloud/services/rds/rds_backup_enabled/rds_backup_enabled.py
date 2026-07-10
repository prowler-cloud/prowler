from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.rds.rds_client import rds_client


class rds_backup_enabled(Check):
    """Check if RDS instances have automated backup enabled."""

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

            if instance.backup_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS instance {instance.name} ({instance.id}) "
                    f"has automated backup enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS instance {instance.name} ({instance.id}) "
                    f"does not have automated backup enabled."
                )

            findings.append(report)

        return findings

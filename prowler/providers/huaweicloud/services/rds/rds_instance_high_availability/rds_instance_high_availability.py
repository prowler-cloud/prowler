from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.rds.rds_client import rds_client


class rds_instance_high_availability(Check):
    """Check if RDS instances have high availability configured."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        """Evaluate high availability for each RDS instance.

        Returns:
            A list of Huawei Cloud check reports.
        """
        findings = []

        for instance in rds_client.instances:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=instance)
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = f"huaweicloud:rds:{instance.region}:{rds_client.audited_account}:instance/{instance.id}"

            if instance.is_ha:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS instance {instance.name} ({instance.id}) "
                    f"has high availability configured."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS instance {instance.name} ({instance.id}) "
                    f"does not have high availability configured (single instance deployment)."
                )

            findings.append(report)

        return findings

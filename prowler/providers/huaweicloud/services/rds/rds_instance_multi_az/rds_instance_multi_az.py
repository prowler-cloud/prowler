from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.rds.rds_client import rds_client


class rds_instance_multi_az(Check):
    """Check if RDS instances are deployed across multiple availability zones."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for instance in rds_client.instances:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=instance)
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = f"huaweicloud:rds:{instance.region}:{rds_client.audited_account}:instance/{instance.id}"

            if instance.is_multi_az:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS instance {instance.name} ({instance.id}) "
                    f"is deployed across multiple availability zones."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS instance {instance.name} ({instance.id}) "
                    f"is deployed in a single availability zone."
                )

            findings.append(report)

        return findings

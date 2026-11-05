from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.rds.rds_client import rds_client


class rds_public_access(Check):
    """Check if RDS instances are not publicly accessible."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for instance in rds_client.instances:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=instance)
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = f"huaweicloud:rds:{instance.region}:{rds_client.audited_account}:instance/{instance.id}"

            if instance.is_public:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS instance {instance.name} ({instance.id}) "
                    f"has a public IP address {instance.public_ip}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS instance {instance.name} ({instance.id}) "
                    f"does not have a public IP address."
                )

            findings.append(report)

        return findings

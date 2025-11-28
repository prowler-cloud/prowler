from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_ssl_enabled(Check):
    """Check if RDS instance requires all incoming connections to use SSL."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for instance in rds_client.instances:
            report = CheckReportAlibabaCloud(
                metadata=self.metadata(), resource=instance
            )
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = f"acs:rds:{instance.region}:{rds_client.audited_account}:dbinstance/{instance.id}"

            if instance.ssl_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS Instance {instance.name} has SSL encryption enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"RDS Instance {instance.name} does not have SSL encryption enabled."

            findings.append(report)

        return findings

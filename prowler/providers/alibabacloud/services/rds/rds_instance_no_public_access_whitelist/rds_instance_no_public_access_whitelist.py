from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_no_public_access_whitelist(Check):
    """Check if RDS Instances are not open to the world."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for instance in rds_client.instances:
            report = CheckReportAlibabaCloud(
                metadata=self.metadata(), resource=instance
            )
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = f"acs:rds:{instance.region}:{rds_client.audited_account}:dbinstance/{instance.id}"

            is_public = False
            for ip in instance.security_ips:
                if ip == "0.0.0.0/0" or ip == "0.0.0.0":
                    is_public = True
                    break

            if not is_public:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS Instance {instance.name} is not open to the world."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"RDS Instance {instance.name} is open to the world (0.0.0.0/0 allowed)."

            findings.append(report)

        return findings

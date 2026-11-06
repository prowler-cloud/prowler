from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client

# Whitelist entries that admit any IPv4 or IPv6 client.
OPEN_WHITELIST_ENTRIES = ("0.0.0.0/0", "0.0.0.0", "::/0")


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

            open_entry = next(
                (ip for ip in instance.security_ips if ip in OPEN_WHITELIST_ENTRIES),
                None,
            )

            if open_entry is None:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS Instance {instance.name} is not open to the world."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"RDS Instance {instance.name} is open to the world ({open_entry} allowed)."

            findings.append(report)

        return findings

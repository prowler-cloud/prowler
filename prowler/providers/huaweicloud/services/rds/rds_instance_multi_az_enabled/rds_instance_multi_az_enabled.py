from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.rds.rds_client import rds_client


class rds_instance_multi_az_enabled(Check):
    """Check if RDS instances are deployed in high availability (Primary/Standby) mode."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for instance in rds_client.instances:
            if instance.instance_type.lower() == "replica":
                continue

            is_ha = (
                instance.instance_type.lower() == "ha"
                or instance.ha_mode.lower() == "ha"
            )
            if is_ha and not instance.availability_zones:
                continue

            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=instance)
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = f"huaweicloud:rds:{instance.region}:{rds_client.audited_account}:instance/{instance.id}"

            is_multi_az = is_ha and len(instance.availability_zones) >= 2
            if is_multi_az:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS instance {instance.name} ({instance.id}) "
                    f"has high availability (Primary/Standby) enabled across multiple AZs."
                )
            elif is_ha:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS instance {instance.name} ({instance.id}) "
                    f"is Primary/Standby but deployed in a single availability zone."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS instance {instance.name} ({instance.id}) "
                    f"does not have high availability (Primary/Standby) enabled."
                )

            findings.append(report)

        return findings

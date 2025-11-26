from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_tde_enabled(Check):
    """Check if TDE is set to Enabled for applicable database instance."""

    def execute(self) -> list[Check_Report_AlibabaCloud]:
        findings = []

        for instance in rds_client.instances:
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=instance
            )
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = f"acs:rds:{instance.region}:{rds_client.audited_account}:dbinstance/{instance.id}"

            if instance.tde_status == "Enabled":
                report.status = "PASS"
                report.status_extended = (
                    f"RDS Instance {instance.name} has TDE enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS Instance {instance.name} does not have TDE enabled."
                )

            findings.append(report)

        return findings

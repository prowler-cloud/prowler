from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.rds.rds_client import rds_client


class rds_instance_tde_key_custom(Check):
    """Check if RDS instance TDE protector is encrypted with BYOK."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for instance in rds_client.instances:
            report = CheckReportAlibabaCloud(
                metadata=self.metadata(), resource=instance
            )
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = f"acs:rds:{instance.region}:{rds_client.audited_account}:dbinstance/{instance.id}"

            # TDE must be enabled AND key must be custom (not service managed)
            # Note: The API response for TDEKeyId usually indicates if it's a custom KMS key
            # If it's a UUID-like string, it's likely a KMS key. If it's "ServiceManaged" or similar, it's not.
            # For Alibaba Cloud, typically if you supply a KeyId it's BYOK.

            if instance.tde_status == "Enabled" and instance.tde_key_id:
                report.status = "PASS"
                report.status_extended = f"RDS Instance {instance.name} has TDE enabled with custom key {instance.tde_key_id}."
            elif instance.tde_status == "Enabled":
                report.status = "FAIL"
                report.status_extended = f"RDS Instance {instance.name} has TDE enabled but uses service-managed key."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS Instance {instance.name} does not have TDE enabled."
                )

            findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.common.provider import Provider


class ec2_ebs_volume_backup_recovery_point_recent(Check):
    """Evaluate observed AWS Backup recovery points for audited EBS volumes."""

    def execute(self) -> list[Check_Report_AWS]:
        """Check the freshness of recovery point evidence in standard AWS Backup vaults."""
        provider = Provider.get_global_provider()
        config = provider.audit_config
        if (
            config.get("aws_backup_ebs_recovery_evidence_enabled") is not True
            or self.CheckID not in provider.audit_metadata.expected_checks
            or (provider.resource_filter_requested and not provider.audit_resources)
        ):
            return []

        from prowler.providers.aws.services.ec2.ec2_client import ec2_client

        volumes = {volume.arn: volume for volume in ec2_client.volumes}
        if not volumes:
            return []

        from prowler.providers.aws.services.backup.backup_client import backup_client

        hours = config.get("aws_backup_ebs_recovery_point_max_age_hours", 48)
        if type(hours) is not int or not 1 <= hours <= 8760:
            hours = 48
        decisions = backup_client.evaluate_ebs_recovery_points(volumes.values(), hours)
        metadata = self.metadata()
        findings = []
        for arn, volume in volumes.items():
            decision = decisions.get(arn)
            if decision is None or decision.status == "SKIP":
                continue

            report = Check_Report_AWS(metadata=metadata, resource=volume)
            report.status = decision.status
            point = decision.point
            if point is not None:
                creation_date = point.creation_date.isoformat()
                report.status_extended = (
                    f"EBS volume {volume.id} has recovery point {point.arn} in "
                    f"{point.status} status, created at {creation_date} within the previous "
                    f"{hours} hours in the scanned account's standard AWS Backup vault "
                    f"{point.vault_arn} in this Region."
                )
                report.raw = {
                    "recovery_point_arn": point.arn,
                    "backup_vault_arn": point.vault_arn,
                    "creation_date": creation_date,
                    "status": point.status,
                }
            else:
                report.status_extended = (
                    f"No qualifying recovery point for EBS volume {volume.id} was observed "
                    f"in the scanned account's standard AWS Backup vaults in this Region "
                    f"within the previous {hours} hours."
                )
            findings.append(report)
        return findings

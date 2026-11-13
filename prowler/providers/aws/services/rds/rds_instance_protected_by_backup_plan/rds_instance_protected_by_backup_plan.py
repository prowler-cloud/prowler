from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.backup.backup_client import backup_client
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_protected_by_backup_plan(Check):
    def execute(self):
        """Evaluate non-Aurora RDS instance coverage by AWS Backup selections.

        Apply selection-local exclusions before the existing inclusion rules.
        Selection coverage does not establish backup completion or restorability.

        Returns:
            A list of findings for collected RDS instances without Aurora engines.
        """
        findings = []
        for db_instance in rds_client.db_instances.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=db_instance)
            # Makes sure the instance is not running with an Aurora engine
            # Aurora backup plans require enabling it separately from RDS
            if db_instance.engine not in [
                "aurora-mysql",
                "aurora",
                "aurora-postgresql",
            ]:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS Instance {db_instance.id} is not protected by a backup plan."
                )

                protected_resources = backup_client.get_protected_resources(
                    db_instance.arn
                )
                if (
                    db_instance.arn in protected_resources
                    or f"arn:{rds_client.audited_partition}:rds:*:*:instance:*"
                    in protected_resources
                    or "*" in protected_resources
                ):
                    report.status = "PASS"
                    report.status_extended = (
                        f"RDS Instance {db_instance.id} is protected by a backup plan."
                    )

                findings.append(report)

        return findings

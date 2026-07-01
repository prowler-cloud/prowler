"""
Prowler check: rds_instance_extended_support

This check fails when an RDS DB instance is enrolled in Amazon RDS Extended Support.
Enrollment is exposed via the "EngineLifecycleSupport" attribute returned by DescribeDBInstances.
"""

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_extended_support(Check):
    def execute(self):
        findings = []

        for db_instance in rds_client.db_instances.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=db_instance)

            # EngineLifecycleSupport can be absent when Extended Support is not applicable.
            lifecycle_support = getattr(db_instance, "engine_lifecycle_support", None)

            if lifecycle_support == "open-source-rds-extended-support":
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS instance {db_instance.id} ({db_instance.engine} {db_instance.engine_version}) "
                    f"is enrolled in RDS Extended Support (EngineLifecycleSupport={lifecycle_support})."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS instance {db_instance.id} ({db_instance.engine} {db_instance.engine_version}) "
                    "is not enrolled in RDS Extended Support."
                )

            findings.append(report)

        return findings

from prowler.config.config import get_config_var
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_deprecated_engine_version(Check):
    def execute(self):
        findings = []
        for instance in rds_client.db_instances:
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.status = "FAIL"
            report.resource_id = instance.id
            report.resource_tags = instance.tags
            report.status_extended = (
                f"RDS instance {instance.id} has a deprecated engine version {instance.engine_version}."
            )
            # Check only depending on the engine
            if instance.engine_version in rds_client.db_engines.keys():
                report.status = "PASS"
                report.status_extended = f"RDS instance {instance.id} does not have a deprecated engine version {instance.engine_version}."

            findings.append(report)

        return findings

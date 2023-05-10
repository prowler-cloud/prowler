from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_deprecated_engine_version(Check):
    def execute(self):
        findings = []

        for instance in rds_client.db_instances:
            available_versions = []

            for iterate_version in rds_client.db_engines:
                if instance.engine == iterate_version.engine:
                    available_versions.append(iterate_version.engine_version)

            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.status = "FAIL"
            report.resource_id = instance.id
            report.resource_tags = instance.tags
            report.status_extended = f"RDS instance {instance.id} is using a deprecated engine {instance.engine} with version {instance.engine_version}."

            if instance.engine_version in available_versions:
                report.status = "PASS"
                report.status_extended = f"RDS instance {instance.id} is not using a deprecated engine {instance.engine} with version {instance.engine_version}."

            findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_iam_authentication_enabled(Check):
    def execute(self):
        supported_engines = [
            "postgres",
            "aurora-postgresql",
            "mysql",
            "mariadb",
            "aurora-mysql",
            "aurora",
        ]
        findings = []
        for db_instance in rds_client.db_instances:
            # Check DB Instance to make sure its not part of a cluster.
            if not db_instance.cluster_id and any(
                engine in db_instance.engine for engine in supported_engines
            ):
                report = Check_Report_AWS(self.metadata())
                report.region = db_instance.region
                report.resource_id = db_instance.id
                report.resource_arn = db_instance.arn
                report.resource_tags = db_instance.tags

                if db_instance.iam_auth:
                    report.status = "PASS"
                    report.status_extended = f"RDS Instance {db_instance.id} which is not clustered has IAM authentication enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"RDS Instance {db_instance.id} which is not clustered does not have IAM authentication enabled."

                findings.append(report)
        return findings

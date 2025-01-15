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
        for db_instance in rds_client.db_instances.values():
            if any(engine in db_instance.engine for engine in supported_engines):
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource_metadata=db_instance
                )
                # Check if is member of a cluster
                if db_instance.cluster_id:
                    if db_instance.iam_auth:
                        report.status = "PASS"
                        report.status_extended = f"RDS Instance {db_instance.id} has IAM authentication enabled at cluster {db_instance.cluster_id} level."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"RDS Instance {db_instance.id} does not have IAM authentication enabled at cluster {db_instance.cluster_id} level."
                else:
                    if db_instance.iam_auth:
                        report.status = "PASS"
                        report.status_extended = f"RDS Instance {db_instance.id} has IAM authentication enabled."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"RDS Instance {db_instance.id} does not have IAM authentication enabled."

                findings.append(report)

        return findings

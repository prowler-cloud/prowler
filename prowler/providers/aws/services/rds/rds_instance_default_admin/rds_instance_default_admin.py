from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_default_admin(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances:
            # Check only RDS DB instances that are not clustered
            if not db_instance.cluster_id:
                report = Check_Report_AWS(self.metadata())
                report.region = db_instance.region
                report.resource_id = db_instance.id
                report.resource_arn = db_instance.arn
                report.resource_tags = db_instance.tags
                report.status = "FAIL"
                report.status_extended = f"RDS Instance {db_instance.id} which is not clustered is using the default master username."

                if db_instance.username not in ["admin", "postgres"]:
                    report.status = "PASS"
                    report.status_extended = f"RDS Instance {db_instance.id} which is not clustered is not using the default master username."

                findings.append(report)

        return findings

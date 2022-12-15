from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_integration_cloudwatch_logs(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances:
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            if db_instance.cloudwatch_logs:
                report.status = "PASS"
                report.status_extended = f"RDS Instance {db_instance.id} is shipping {' '.join(db_instance.cloudwatch_logs)} to CloudWatch Logs."
            else:
                report.status = "FAIL"
                report.status_extended = f"RDS Instance {db_instance.id} does not have CloudWatch Logs enabled."

            findings.append(report)

        return findings

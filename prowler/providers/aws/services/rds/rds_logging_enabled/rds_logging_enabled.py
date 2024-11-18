from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_logging_enabled(Check):
    def execute(self):
        findings = []
        valid_statuses = [
            "available",
            "backing-up",
            "storage-optimization",
            "storage-full",
        ]

        for (
            db_instance
        ) in (
            rds_client.db_instances.values()
        ):  # Use .values() to iterate over dictionary items
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            report.resource_arn = db_instance.arn
            report.resource_tags = db_instance.tags

            # Check if the status of the instance is valid for the logging check
            if db_instance.status not in valid_statuses:
                report.status = "NOT_APPLICABLE"
                report.status_extended = f"RDS Instance {db_instance.id} is in '{db_instance.status}' status and is not applicable for logging check."
            else:
                if db_instance.cloudwatch_logs:
                    report.status = "PASS"
                    report.status_extended = f"RDS Instance {db_instance.id} has the following logs enabled: {', '.join(db_instance.cloudwatch_logs)}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"RDS Instance {db_instance.id} does not have any CloudWatch logs enabled."

            findings.append(report)

        return findings

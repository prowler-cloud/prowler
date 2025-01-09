from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.backup.backup_client import backup_client
from prowler.providers.aws.services.dynamodb.dynamodb_client import dynamodb_client


class dynamodb_table_protected_by_backup_plan(Check):
    def execute(self):
        findings = []
        for table_arn, table in dynamodb_client.tables.items():
            report = Check_Report_AWS(self.metadata())
            report.resource_id = table.name
            report.resource_arn = table_arn
            report.resource_tags = table.tags
            report.region = table.region
            report.status = "FAIL"
            report.status_extended = (
                f"DynamoDB table {table.name} is not protected by a backup plan."
            )

            if (
                table_arn in backup_client.protected_resources
                or f"arn:{dynamodb_client.audited_partition}:dynamodb:*:*:table/*"
                in backup_client.protected_resources
                or "*" in backup_client.protected_resources
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"DynamoDB table {table.name} is protected by a backup plan."
                )

            findings.append(report)

        return findings

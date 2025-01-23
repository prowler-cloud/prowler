from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dynamodb.dynamodb_client import dynamodb_client


class dynamodb_table_deletion_protection_enabled(Check):
    def execute(self):
        findings = []
        for table in dynamodb_client.tables.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=table)
            report.status = "FAIL"
            report.status_extended = f"DynamoDB table {table.name} does not have deletion protection enabled."

            if table.deletion_protection:
                report.status = "PASS"
                report.status_extended = (
                    f"DynamoDB table {table.name} has deletion protection enabled."
                )

            findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dynamodb.dynamodb_client import dynamodb_client


class dynamodb_tables_pitr_enabled(Check):
    def execute(self):
        findings = []
        for table in dynamodb_client.tables.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource_metadata=table)
            report.status = "FAIL"
            report.status_extended = f"DynamoDB table {table.name} does not have point-in-time recovery enabled."
            if table.pitr:
                report.status = "PASS"
                report.status_extended = (
                    f"DynamoDB table {table.name} has point-in-time recovery enabled."
                )
            findings.append(report)
        return findings

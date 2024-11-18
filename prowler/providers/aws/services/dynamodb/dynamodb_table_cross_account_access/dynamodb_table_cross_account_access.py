from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dynamodb.dynamodb_client import dynamodb_client
from prowler.providers.aws.services.iam.lib.policy import is_policy_public


class dynamodb_table_cross_account_access(Check):
    def execute(self):
        findings = []
        for table_arn, table in dynamodb_client.tables.items():
            report = Check_Report_AWS(self.metadata())
            report.resource_id = table.name
            report.resource_arn = table_arn
            report.resource_tags = table.tags
            report.region = table.region
            report.status = "PASS"
            report.status_extended = (
                f"DynamoDB table {table.name} does not have a resource-based policy."
            )
            if table.policy:
                report.status_extended = f"DynamoDB table {table.name} has a resource-based policy but is not cross account."
                if is_policy_public(
                    table.policy,
                    dynamodb_client.audited_account,
                    is_cross_account_allowed=False,
                ):
                    report.status = "FAIL"
                    report.status_extended = f"DynamoDB table {table.name} has a resource-based policy allowing cross account access."
            findings.append(report)
        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dynamodb.dynamodb_client import dynamodb_client
from prowler.providers.aws.services.iam.lib.policy import is_policy_public


class dynamodb_table_cross_account_access(Check):
    def execute(self):
        findings = []
        trusted_account_ids = dynamodb_client.audit_config.get(
            "trusted_account_ids", []
        )
        for table in dynamodb_client.tables.values():
            if table.policy is None:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=table)
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
                    trusted_account_ids=trusted_account_ids,
                ):
                    report.status = "FAIL"
                    report.status_extended = f"DynamoDB table {table.name} has a resource-based policy allowing cross account access."
            findings.append(report)
        return findings

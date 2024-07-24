from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.lib.policy_condition_parser.policy_condition_parser import (
    is_condition_block_restrictive,
)
from prowler.providers.aws.services.dynamodb.dynamodb_client import dynamodb_client


class dynamodb_table_cross_account_access(Check):
    def execute(self):
        findings = []
        for table in dynamodb_client.tables:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = table.name
            report.resource_arn = table.arn
            report.resource_tags = table.tags
            report.region = table.region
            report.status = "PASS"
            report.status_extended = (
                f"DynamoDB table {table.name} does not have a resource-based policy."
            )
            if table.policy:
                report.status_extended = f"DynamoDB table {table.name} has a resource-based policy but is not cross account."
                cross_account_access = False
                policy_statements = table.policy["Statement"]
                if isinstance(
                    policy_statements, dict
                ):  # Normalize single statement to list
                    policy_statements = [policy_statements]
                for statement in policy_statements:
                    if not cross_account_access:
                        if statement["Effect"] == "Allow":
                            if "AWS" in statement["Principal"]:
                                principals = statement["Principal"]["AWS"]
                                if not isinstance(principals, list):
                                    principals = [principals]
                            else:
                                principals = [statement["Principal"]]
                            for aws_account in principals:
                                if (
                                    dynamodb_client.audited_account not in aws_account
                                    or "*" == aws_account
                                ):
                                    cross_account_access = True
                                    # Check if the condition block is restrictive
                                    conditions = statement.get("Condition", {})
                                    if is_condition_block_restrictive(
                                        conditions, dynamodb_client.audited_account
                                    ):
                                        cross_account_access = False
                    else:
                        break
                if cross_account_access:
                    report.status = "FAIL"
                    report.status_extended = f"DynamoDB table {table.name} has a resource-based policy allowing cross account access."
            findings.append(report)
        return findings

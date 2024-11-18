from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client
from prowler.providers.aws.services.iam.lib.policy import is_policy_public


class awslambda_function_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = function.region
            report.resource_id = function.name
            report.resource_arn = function.arn
            report.resource_tags = function.tags

            report.status = "PASS"
            report.status_extended = f"Lambda function {function.name} has a policy resource-based policy not public."
            if is_policy_public(
                function.policy,
                awslambda_client.audited_account,
                is_cross_account_allowed=True,
            ):
                report.status = "FAIL"
                report.status_extended = f"Lambda function {function.name} has a policy resource-based policy with public access."

            findings.append(report)

        return findings

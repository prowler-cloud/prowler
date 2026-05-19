from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.check.resource_limit import get_resource_scan_limit, limited_findings
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client
from prowler.providers.aws.services.iam.lib.policy import is_policy_public


class awslambda_function_not_publicly_accessible(Check):
    def execute(self):
        def evaluate(function):
            if function.policy is None:
                return None
            report = Check_Report_AWS(metadata=self.metadata(), resource=function)

            report.status = "PASS"
            report.status_extended = f"Lambda function {function.name} has a resource-based policy without public access."
            if is_policy_public(
                function.policy,
                awslambda_client.audited_account,
                is_cross_account_allowed=True,
            ):
                report.status = "FAIL"
                report.status_extended = f"Lambda function {function.name} has a resource-based policy with public access."

            return report

        return limited_findings(
            awslambda_client.iter_functions(),
            evaluate,
            get_resource_scan_limit(
                awslambda_client.audit_config, "max_lambda_functions"
            ),
        )

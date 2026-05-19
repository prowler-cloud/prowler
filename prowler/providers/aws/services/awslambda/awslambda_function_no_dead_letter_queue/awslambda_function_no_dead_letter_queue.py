from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.check.resource_limit import get_resource_scan_limit, limited_findings
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_no_dead_letter_queue(Check):
    def execute(self):
        def evaluate(function):
            report = Check_Report_AWS(metadata=self.metadata(), resource=function)
            if function.dead_letter_config:
                report.status = "PASS"
                report.status_extended = f"Lambda function {function.name} has a Dead Letter Queue configured at {function.dead_letter_config.target_arn}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Lambda function {function.name} does not have a Dead Letter Queue configured."
            return report

        return limited_findings(
            awslambda_client.iter_functions(),
            evaluate,
            get_resource_scan_limit(
                awslambda_client.audit_config, "max_lambda_functions"
            ),
        )

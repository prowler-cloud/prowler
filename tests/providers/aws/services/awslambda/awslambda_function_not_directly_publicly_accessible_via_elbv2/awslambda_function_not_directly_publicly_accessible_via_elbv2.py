from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client

class awslambda_function_not_directly_publicly_accessible_via_elbv2(Check):
    def execute(self):
        findings = []
        public_lambda_funcs = {}

        for tg in elbv2_client.target_groups:
            if tg.target_type == 'lambda':
                public_lambda_funcs[tg.target] = tg.lbdns

        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = function.region
            report.resource_id = function.name
            report.resource_arn = function.arn
            report.resource_tags = function.tags
            report.status = "PASS"
            report.status_extended = f"Lambda function {function.name} is not behind a internet facing load balancer."

            if function.arn in public_lambda_funcs:
                report.status = "FAIL"
                report.status_extended = f"Lambda function {function.name} is behind a internet facing load balancer {public_lambda_funcs[function.arn]}."
            findings.append(report)
        return findings
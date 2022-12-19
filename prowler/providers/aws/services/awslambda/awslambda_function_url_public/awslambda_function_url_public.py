from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client
from prowler.providers.aws.services.awslambda.awslambda_service import AuthType


class awslambda_function_url_public(Check):
    def execute(self):
        findings = []
        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = function.region
            report.resource_id = function.name
            report.resource_arn = function.arn
            if function.url_config:
                if function.url_config.auth_type == AuthType.AWS_IAM:
                    report.status = "PASS"
                    report.status_extended = f"Lambda function {function.name} has not a publicly accessible function URL"
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Lambda function {function.name} has a publicly accessible function URL"

                findings.append(report)

        return findings

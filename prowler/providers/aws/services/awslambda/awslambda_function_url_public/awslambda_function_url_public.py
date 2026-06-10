from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client
from prowler.providers.aws.services.awslambda.awslambda_service import AuthType


class awslambda_function_url_public(Check):
    def execute(self):
        reports = []
        for function in awslambda_client.iter_functions():
            if not function.url_config:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=function)

            if function.url_config.auth_type == AuthType.AWS_IAM:
                report.status = "PASS"
                report.status_extended = f"Lambda function {function.name} does not have a publicly accessible function URL."
            else:
                report.status = "FAIL"
                report.status_extended = f"Lambda function {function.name} has a publicly accessible function URL."

            reports.append(report)
        return reports

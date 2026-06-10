from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_url_cors_policy(Check):
    def execute(self):
        def evaluate(function):
            if not function.url_config:
                return None
            report = Check_Report_AWS(metadata=self.metadata(), resource=function)

            if "*" in function.url_config.cors_config.allow_origins:
                report.status = "FAIL"
                report.status_extended = f"Lambda function {function.name} URL has a wide CORS configuration."
            else:
                report.status = "PASS"
                report.status_extended = f"Lambda function {function.name} does not have a wide CORS configuration."

            return report

        reports = []
        for resource in awslambda_client.iter_functions():
            report = evaluate(resource)
            if report is not None:
                reports.append(report)
        return reports

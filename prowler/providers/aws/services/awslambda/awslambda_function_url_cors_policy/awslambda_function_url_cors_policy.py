from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_url_cors_policy(Check):
    def execute(self):
        findings = []
        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=function
            )

            if function.url_config:
                if "*" in function.url_config.cors_config.allow_origins:
                    report.status = "FAIL"
                    report.status_extended = f"Lambda function {function.name} URL has a wide CORS configuration."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Lambda function {function.name} does not have a wide CORS configuration."

                findings.append(report)

        return findings

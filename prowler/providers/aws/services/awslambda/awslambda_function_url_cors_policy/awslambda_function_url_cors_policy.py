from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_url_cors_policy(Check):
    def execute(self):
        findings = []
        functions = awslambda_client.functions.values()
        self.start_task("Processing functions...", len(functions))
        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = function.region
            report.resource_id = function.name
            report.resource_arn = function.arn
            report.resource_tags = function.tags
            if function.url_config:
                if "*" in function.url_config.cors_config.allow_origins:
                    report.status = "FAIL"
                    report.status_extended = f"Lambda function {function.name} URL has a wide CORS configuration."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Lambda function {function.name} does not have a wide CORS configuration."

                findings.append(report)
            self.increment_task_progress()
        self.update_title_with_findings(findings)
        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_using_supported_runtimes(Check):
    def execute(self):
        findings = []
        functions = awslambda_client.functions.values()
        self.start_task("Processing functions...", len(functions))
        for function in awslambda_client.functions.values():
            if function.runtime:
                report = Check_Report_AWS(self.metadata())
                report.region = function.region
                report.resource_id = function.name
                report.resource_arn = function.arn
                report.resource_tags = function.tags

                if function.runtime in awslambda_client.audit_config.get(
                    "obsolete_lambda_runtimes", []
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Lambda function {function.name} is using {function.runtime} which is obsolete."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Lambda function {function.name} is using {function.runtime} which is supported."

                findings.append(report)
            self.increment_task_progress()

        self.update_title_with_findings(findings)
        return findings

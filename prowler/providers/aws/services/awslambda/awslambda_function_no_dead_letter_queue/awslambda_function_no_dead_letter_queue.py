from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_no_dead_letter_queue(Check):
    def execute(self):
        findings = []
        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=function)
            if function.dead_letter_config:
                report.status = "PASS"
                report.status_extended = f"Lambda function {function.name} has a Dead Letter Queue configured at {function.dead_letter_config.target_arn}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Lambda function {function.name} does not have a Dead Letter Queue configured."
            findings.append(report)
        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudwatch.cloudwatch_client import cloudwatch_client
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class cloudwatch_alarm_for_lambda_error_rate(Check):
    def execute(self):
        findings = []

        # Define the expected metric name and namespace for Lambda errors
        expected_metric_name = 'Errors'
        expected_namespace = 'AWS/Lambda'

        for function in awslambda_client.functions.values():

            report = Check_Report_AWS(metadata=self.metadata(), resource=function)
            report.resource_tags = function.tags
            report.status = "FAIL"
            report.status_extended = f"No CloudWatch alarms found for Lambda function '{function.name}' error rate."

            alarms_found = any(
                alarm.metric == expected_metric_name and alarm.name_space == expected_namespace
                for alarm in cloudwatch_client.metric_alarms
            )

            if alarms_found:
                report.status = "PASS"
                report.status_extended = f"CloudWatch alarm(s) found for Lambda function '{function.name}' error rate."

            findings.append(report)

        return findings

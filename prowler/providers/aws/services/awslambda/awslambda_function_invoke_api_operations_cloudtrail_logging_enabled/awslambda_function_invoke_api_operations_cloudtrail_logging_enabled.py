from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)


class awslambda_function_invoke_api_operations_cloudtrail_logging_enabled(Check):
    def execute(self):
        findings = []
        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = function.region
            report.resource_id = function.name
            report.resource_arn = function.arn

            report.status = "FAIL"
            report.status_extended = (
                f"Lambda function {function.name} is not recorded by CloudTrail"
            )
            lambda_recorded_cloudtrail = False
            for trail in cloudtrail_client.trails:
                for data_event in trail.data_events:
                    for resource in data_event["DataResources"]:
                        if (
                            resource["Type"] == "AWS::Lambda::Function"
                            and function.arn in resource["Values"]
                        ):
                            lambda_recorded_cloudtrail = True
                            break

                    if lambda_recorded_cloudtrail:
                        break
                if lambda_recorded_cloudtrail:
                    report.status = "PASS"
                    report.status_extended = f"Lambda function {function.name} is recorded by CloudTrail {trail.name}"
                    break
            findings.append(report)

        return findings

from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_inside_vpc(Check):
    def execute(self) -> List[Check_Report_AWS]:
        findings = []
        for function_arn, function in awslambda_client.functions.items():
            report = Check_Report_AWS(self.metadata())
            report.region = function.region
            report.resource_id = function.name
            report.resource_arn = function_arn
            report.resource_tags = function.tags
            report.status = "PASS"
            report.status_extended = (
                f"Lambda function {function.name} is inside of VPC {function.vpc_id}"
            )

            if not function.vpc_id:
                awslambda_client.set_failed_check(
                    self.__class__.__name__,
                    function_arn,
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"Lambda function {function.name} is not inside a VPC"
                )

            findings.append(report)

        return findings

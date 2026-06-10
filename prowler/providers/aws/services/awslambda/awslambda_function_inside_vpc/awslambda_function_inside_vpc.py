from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_inside_vpc(Check):
    def execute(self) -> List[Check_Report_AWS]:
        def evaluate(function):
            report = Check_Report_AWS(metadata=self.metadata(), resource=function)

            report.status = "PASS"
            report.status_extended = (
                f"Lambda function {function.name} is inside of VPC {function.vpc_id}"
            )

            if not function.vpc_id:
                awslambda_client.set_failed_check(
                    self.__class__.__name__,
                    function.arn,
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"Lambda function {function.name} is not inside a VPC"
                )

            return report

        reports = []
        for resource in awslambda_client.iter_functions():
            report = evaluate(resource)
            if report is not None:
                reports.append(report)
        return reports

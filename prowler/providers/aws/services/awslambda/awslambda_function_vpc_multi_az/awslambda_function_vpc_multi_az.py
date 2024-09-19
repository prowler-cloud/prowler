from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client
from prowler.providers.aws.services.awslambda.awslambda_function_inside_vpc.awslambda_function_inside_vpc import (
    awslambda_function_inside_vpc,
)
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class awslambda_function_vpc_multi_az(Check):
    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        LAMBDA_MIN_AZS = awslambda_client.audit_config.get("lambda_min_azs", 2)
        for function_arn, function in awslambda_client.functions.items():
            # only proceed if check "awslambda_function_inside_vpc" did not run or did not FAIL to avoid to report that the function is not inside a VPC twice
            if not awslambda_client.is_failed_check(
                awslambda_function_inside_vpc.__name__,
                function_arn,
            ):
                report = Check_Report_AWS(self.metadata())
                report.region = function.region
                report.resource_id = function.name
                report.resource_arn = function_arn
                report.resource_tags = function.tags
                report.status = "FAIL"
                report.status_extended = (
                    f"Lambda function {function.name} is not inside a VPC."
                )

                if function.vpc_id:
                    function_availability_zones = {
                        getattr(
                            vpc_client.vpc_subnets.get(subnet_id),
                            "availability_zone",
                            None,
                        )
                        for subnet_id in function.subnet_ids
                        if subnet_id in vpc_client.vpc_subnets
                    }

                    if len(function_availability_zones) >= LAMBDA_MIN_AZS:
                        report.status = "PASS"
                        report.status_extended = f"Lambda function {function.name} is inside of VPC {function.vpc_id} that spans in at least {LAMBDA_MIN_AZS} AZs: {', '.join(function_availability_zones)}."
                    else:
                        report.status_extended = f"Lambda function {function.name} is inside of VPC {function.vpc_id} that spans only in {len(function_availability_zones)} AZs: {', '.join(function_availability_zones)}. Must span in at least {LAMBDA_MIN_AZS} AZs."

                findings.append(report)

        return findings

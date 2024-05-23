from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class awslambda_function_not_directly_publicly_accessible_via_elbv2(Check):
    def execute(self):
        findings = []

        public_lambda_functions = {}
        for target_group in elbv2_client.target_groups:
            if (
                target_group.loadbalancer.public
                and target_group.target_type == "lambda"
            ):
                for function in awslambda_client.functions.values():
                    public_access = False
                    if function.arn == target_group.target and function.policy:
                        for statement in function.policy["Statement"]:
                            # Only check allow statements
                            if statement["Effect"] == "Allow":
                                if (
                                    "*" in statement["Principal"]
                                    or (
                                        "AWS" in statement["Principal"]
                                        and "*" in statement["Principal"]["AWS"]
                                    )
                                    or (
                                        "CanonicalUser" in statement["Principal"]
                                        and "*"
                                        in statement["Principal"]["CanonicalUser"]
                                    )
                                ):
                                    public_access = True
                                    break
                    if public_access:
                        public_lambda_functions[target_group.target] = (
                            target_group.loadbalancer
                        )

        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = function.region
            report.resource_id = function.name
            report.resource_arn = function.arn
            report.resource_tags = function.tags
            report.status = "PASS"
            report.status_extended = f"Lambda function {function.name} is not publicly accesible through an Internet facing Load Balancer."

            if function.arn in public_lambda_functions:
                report.status = "FAIL"
                report.status_extended = f"Lambda function {function.name} is publicly accesible through an Internet facing Load Balancer through load balancer {public_lambda_functions[function.arn].dns}."
            findings.append(report)

        return findings

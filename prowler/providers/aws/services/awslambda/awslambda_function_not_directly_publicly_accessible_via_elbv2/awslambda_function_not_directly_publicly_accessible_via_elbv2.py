from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class awslambda_function_not_directly_publicly_accessible_via_elbv2(Check):
    def execute(self):
        findings = []

        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = function.region
            report.resource_id = function.name
            report.resource_arn = function.arn
            report.resource_tags = function.tags
            report.status = "PASS"
            report.status_extended = f"Lambda function {function.name} is not publicly accesible through an Internet facing Load Balancer."

            for target_group in elbv2_client.target_groups:
                # Lambda targets group len must be 1 by definition
                if (
                    target_group.target_type == "lambda"
                    and target_group.targets[0] == function.arn
                ):
                    for lb in elbv2_client.loadbalancersv2:
                        if lb.arn == target_group.load_balancer_arn and lb.public:
                            # Check that function policy is not public
                            for statement in function.policy.get("Statement", []):
                                if statement["Effect"] == "Allow":
                                    if (
                                        "*" in statement["Principal"]
                                        or (
                                            "*" in statement["Principal"].get("AWS", "")
                                        )
                                        or (
                                            "*"
                                            in statement["Principal"].get(
                                                "CanonicalUser", ""
                                            )
                                        )
                                    ):
                                        report.status = "FAIL"
                                        report.status_extended = f"Lambda function {function.name} is publicly accesible through an Internet facing Load Balancer through load balancer {lb.dns}."
                                        break

            findings.append(report)

        return findings

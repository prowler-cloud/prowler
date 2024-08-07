from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class awslambda_function_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = function.region
            report.resource_id = function.name
            report.resource_arn = function.arn
            report.resource_tags = function.tags

            report.status = "PASS"
            report.status_extended = (
                f"Lambda function {function.name} is not publicly accessible."
            )

            # 1. Check if the function is associated with a public load balancer
            target_group_redirects_alb_to_function = ""

            for tg_arn, target_group in elbv2_client.target_groups.items():
                if (
                    target_group.target_type == "lambda"
                ) and function.arn in target_group.targets:
                    for lb_arn in target_group.load_balancer_arns:
                        lb = elbv2_client.loadbalancersv2.get(
                            lb_arn,
                            None,  # Bug: If prowler is filtering by ARN, this will fail because loadbalancersv2 are filtered
                        )
                        if lb and lb.scheme == "internet-facing":
                            target_group_redirects_alb_to_function = tg_arn
                            break

            public_policy = False

            # 2. Check if the function policy allows public access
            if target_group_redirects_alb_to_function and function.policy:
                for statement in function.policy["Statement"]:
                    # Only check allow statements
                    if (
                        statement["Effect"] == "Allow"
                        and (
                            "*" in statement["Principal"]
                            or "*" in statement["Principal"].get("AWS", "")
                            or "*" in statement["Principal"].get("CanonicalUser", "")
                            or "elasticloadbalancing.amazonaws.com"
                            == statement["Principal"].get("Service", "")
                        )
                        and (
                            "*" in statement["Action"]
                            or "lambda:InvokeFunction" in statement["Action"]
                        )
                        and (
                            "*" in statement["Resource"]
                            or function.arn in statement["Resource"]
                        )
                    ):
                        if statement.get("Condition", {}):
                            if (
                                statement["Condition"]
                                .get("ArnLike", {})
                                .get("AWS:SourceArn", "")
                                == target_group_redirects_alb_to_function
                            ):
                                public_policy = True
                                break
                        else:
                            public_policy = True
                            break

            if public_policy:
                report.status = "FAIL"
                report.status_extended = (
                    f"Lambda function {function.name} is publicly accessible."
                )

            findings.append(report)

        return findings

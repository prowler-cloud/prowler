from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


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
<<<<<<< HEAD
            report.status_extended = f"Lambda function {function.name} has a policy resource-based policy not public."

            public_access = False
            if function.policy:
                for statement in function.policy["Statement"]:
                    # Only check allow statements
                    if statement["Effect"] == "Allow" and (
                        "*" in statement["Principal"]
                        or (
                            isinstance(statement["Principal"], dict)
                            and (
                                "*" in statement["Principal"].get("AWS", "")
                                or "*"
                                in statement["Principal"].get("CanonicalUser", "")
                                or (  # Check if function can be invoked by other AWS services
                                    (
                                        ".amazonaws.com"
                                        in statement["Principal"].get("Service", "")
                                    )
                                    and (
                                        "*" in statement.get("Action", "")
                                        or "InvokeFunction"
                                        in statement.get("Action", "")
                                    )
                                )
                            )
                        )
                    ):
                        public_access = True
                        break

            if public_access:
=======
            report.status_extended = f"Lambda function {function.name} has a resource-based policy without public access."
            if is_policy_public(
                function.policy,
                awslambda_client.audited_account,
                is_cross_account_allowed=True,
            ):
>>>>>>> 3f03dd20e (fix(aws) wording of report.status_extended in awslambda_function_not_publicly_accessible (#6824))
                report.status = "FAIL"
                report.status_extended = f"Lambda function {function.name} has a resource-based policy with public access."

            findings.append(report)

        return findings

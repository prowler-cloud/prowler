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

            report.status = "PASS"
            report.status_extended = f"Lambda function {function.name} has a policy resource-based policy not public"

            public_access = False
            if function.policy:
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
                                and "*" in statement["Principal"]["CanonicalUser"]
                            )
                        ):
                            public_access = True
                            break

            if public_access:
                report.status = "FAIL"
                report.status_extended = f"Lambda function {function.name} has a policy resource-based policy with public access"

            findings.append(report)

        return findings

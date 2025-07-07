from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_no_custom_policy_permissive_role_assumption(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        def resource_has_wildcard(resource):
            if isinstance(resource, str):
                return "*" in resource
            if isinstance(resource, list):
                return any("*" in r for r in resource)
            return False

        for policy in iam_client.policies:
            # Check only custom policies
            if policy.type == "Custom":
                report = Check_Report_AWS(metadata=self.metadata(), resource=policy)
                report.region = iam_client.region
                report.status = "PASS"
                report.status_extended = f"Custom Policy {policy.name} does not allow permissive STS Role assumption."

                if policy.document:
                    if not isinstance(policy.document["Statement"], list):
                        policy_statements = [policy.document["Statement"]]
                    else:
                        policy_statements = policy.document["Statement"]
                    for statement in policy_statements:
                        if (
                            statement.get("Effect") == "Allow"
                            and "Action" in statement
                            and "Resource" in statement
                            and resource_has_wildcard(statement["Resource"])
                        ):
                            actions = (
                                statement["Action"]
                                if isinstance(statement["Action"], list)
                                else [statement["Action"]]
                            )
                            for action in actions:
                                if action in ["sts:AssumeRole", "sts:*", "*"]:
                                    report.status = "FAIL"
                                    report.status_extended = f"Custom Policy {policy.name} allows permissive STS Role assumption."
                                    break
                            if report.status == "FAIL":
                                break

                findings.append(report)

        return findings

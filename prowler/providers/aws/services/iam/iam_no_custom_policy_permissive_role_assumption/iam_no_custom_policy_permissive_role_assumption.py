from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_no_custom_policy_permissive_role_assumption(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for index, policy_document in enumerate(iam_client.list_policies_version):
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_arn = iam_client.policies[index]["Arn"]
            report.resource_id = iam_client.policies[index]["PolicyName"]
            report.status = "PASS"
            report.status_extended = f"Custom Policy {iam_client.policies[index]['PolicyName']} does not allow permissive STS Role assumption"
            if type(policy_document["Statement"]) != list:
                policy_statements = [policy_document["Statement"]]
            else:
                policy_statements = policy_document["Statement"]
            for statement in policy_statements:
                if (
                    statement["Effect"] == "Allow"
                    and "Action" in statement
                    and (
                        "sts:AssumeRole" in statement["Action"]
                        or "sts:*" in statement["Action"]
                        or "*" in statement["Action"]
                    )
                    and "*" in statement["Resource"]
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Custom Policy {iam_client.policies[index]['PolicyName']} allows permissive STS Role assumption"
                    break

            findings.append(report)

        return findings

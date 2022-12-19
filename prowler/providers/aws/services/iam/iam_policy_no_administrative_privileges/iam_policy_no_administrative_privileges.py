from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_policy_no_administrative_privileges(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for index, policy_document in enumerate(iam_client.list_policies_version):
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_arn = iam_client.policies[index]["Arn"]
            report.resource_id = iam_client.policies[index]["PolicyName"]
            report.status = "PASS"
            report.status_extended = f"Policy {iam_client.policies[index]['PolicyName']} does not allow '*:*' administrative privileges"
            # Check the statements, if one includes *:* stop iterating over the rest
            for statement in policy_document["Statement"]:
                if (
                    statement["Effect"] == "Allow"
                    and "*" in statement["Action"]
                    and "*" in statement["Resource"]
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Policy {iam_client.policies[index]['PolicyName']} allows '*:*' administrative privileges"
                    break

            findings.append(report)
        return findings

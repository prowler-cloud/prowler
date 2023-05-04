from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_role_cross_account_readonlyaccess_policy(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for role in iam_client.roles:
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_arn = role.arn
            report.resource_id = role.name
            report.resource_tags = role.tags
            report.status = "PASS"
            report.status_extended = (
                f"IAM Role {role.name} has not ReadOnlyAccess policy"
            )
            for policy in role.attached_policies:
                if policy["PolicyName"] == "ReadOnlyAccess":
                    report.status_extended = f"IAM Role {role.name} has read-only access but is not cross account"
                    if type(role.assume_role_policy["Statement"]) == list:
                        for statement in role.assume_role_policy["Statement"]:
                            if (
                                statement["Effect"] == "Allow"
                                and "AWS" in statement["Principal"]
                            ):
                                if type(statement["Principal"]["AWS"]) == list:
                                    for aws_account in statement["Principal"]["AWS"]:
                                        if (
                                            iam_client.account not in aws_account
                                            or "*" == aws_account
                                        ):
                                            report.status = "FAIL"
                                            report.status_extended = f"IAM Role {role.name} gives cross account read-only access!"
                                            break
                                else:
                                    if (
                                        iam_client.account
                                        not in statement["Principal"]["AWS"]
                                        or "*" == statement["Principal"]["AWS"]
                                    ):
                                        report.status = "FAIL"
                                        report.status_extended = f"IAM Role {role.name} gives cross account read-only access!"
                    else:
                        statement = role.assume_role_policy["Statement"]
                        if (
                            statement["Effect"] == "Allow"
                            and "AWS" in statement["Principal"]
                        ):
                            if type(statement["Principal"]["AWS"]) == list:
                                for aws_account in statement["Principal"]["AWS"]:
                                    if (
                                        iam_client.account not in aws_account
                                        or "*" == aws_account
                                    ):
                                        report.status = "FAIL"
                                        report.status_extended = f"IAM Role {role.name} gives cross account read-only access!"
                                        break
                            else:
                                if (
                                    iam_client.account
                                    not in statement["Principal"]["AWS"]
                                    or "*" == statement["Principal"]["AWS"]
                                ):
                                    report.status = "FAIL"
                                    report.status_extended = f"IAM Role {role.name} gives cross account read-only access!"

            findings.append(report)

        return findings

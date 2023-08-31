from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_role_cross_account_readonlyaccess_policy(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for role in iam_client.roles:
            if (
                not role.is_service_role
            ):  # Avoid service roles since they cannot be modified by the user
                report = Check_Report_AWS(self.metadata())
                report.region = iam_client.region
                report.resource_arn = role.arn
                report.resource_id = role.name
                report.resource_tags = role.tags
                report.status = "PASS"
                report.status_extended = (
                    f"IAM Role {role.name} does not have ReadOnlyAccess policy."
                )
                for policy in role.attached_policies:
                    if policy["PolicyName"] == "ReadOnlyAccess":
                        report.status_extended = f"IAM Role {role.name} has read-only access but is not cross account."
                        cross_account_access = False
                        if isinstance(role.assume_role_policy["Statement"], list):
                            for statement in role.assume_role_policy["Statement"]:
                                if not cross_account_access:
                                    if (
                                        statement["Effect"] == "Allow"
                                        and "AWS" in statement["Principal"]
                                    ):
                                        if isinstance(
                                            statement["Principal"]["AWS"], list
                                        ):
                                            for aws_account in statement["Principal"][
                                                "AWS"
                                            ]:
                                                if (
                                                    iam_client.audited_account
                                                    not in aws_account
                                                    or "*" == aws_account
                                                ):
                                                    cross_account_access = True
                                                    break
                                        else:
                                            if (
                                                iam_client.audited_account
                                                not in statement["Principal"]["AWS"]
                                                or "*" == statement["Principal"]["AWS"]
                                            ):
                                                cross_account_access = True
                                else:
                                    break
                        else:
                            statement = role.assume_role_policy["Statement"]
                            if (
                                statement["Effect"] == "Allow"
                                and "AWS" in statement["Principal"]
                            ):
                                if isinstance(statement["Principal"]["AWS"], list):
                                    for aws_account in statement["Principal"]["AWS"]:
                                        if (
                                            iam_client.audited_account
                                            not in aws_account
                                            or "*" == aws_account
                                        ):
                                            cross_account_access = True
                                            break
                                else:
                                    if (
                                        iam_client.audited_account
                                        not in statement["Principal"]["AWS"]
                                        or "*" == statement["Principal"]["AWS"]
                                    ):
                                        cross_account_access = True
                        if cross_account_access:
                            report.status = "FAIL"
                            report.status_extended = f"IAM Role {role.name} gives cross account read-only access."

                findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import (
    is_condition_block_restrictive,
    is_condition_block_restrictive_organization,
    is_condition_block_restrictive_sns_endpoint,
)
from prowler.providers.aws.services.sns.sns_client import sns_client


class sns_topics_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for topic in sns_client.topics:
            report = Check_Report_AWS(metadata=self.metadata(), resource=topic)
            report.status = "PASS"
            report.status_extended = (
                f"SNS topic {topic.name} is not publicly accessible."
            )
            if topic.policy:
                for statement in topic.policy["Statement"]:
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
                            condition_account = False
                            condition_org = False
                            condition_endpoint = False
                            if (
                                "Condition" in statement
                                and is_condition_block_restrictive(
                                    statement["Condition"],
                                    sns_client.audited_account,
                                )
                            ):
                                condition_account = True
                            if (
                                "Condition" in statement
                                and is_condition_block_restrictive_organization(
                                    statement["Condition"],
                                )
                            ):
                                condition_org = True
                            if (
                                "Condition" in statement
                                and is_condition_block_restrictive_sns_endpoint(
                                    statement["Condition"],
                                )
                            ):
                                condition_endpoint = True

                            if condition_account and condition_org:
                                report.status_extended = f"SNS topic {topic.name} is not public because its policy only allows access from the account {sns_client.audited_account} and an organization."
                            elif condition_account:
                                report.status_extended = f"SNS topic {topic.name} is not public because its policy only allows access from the account {sns_client.audited_account}."
                            elif condition_org:
                                report.status_extended = f"SNS topic {topic.name} is not public because its policy only allows access from an organization."
                            elif condition_endpoint:
                                report.status_extended = f"SNS topic {topic.name} is not public because its policy only allows access from an endpoint."
                            else:
                                report.status = "FAIL"
                                report.status_extended = f"SNS topic {topic.name} is public because its policy allows public access."
                                break

            findings.append(report)

        return findings

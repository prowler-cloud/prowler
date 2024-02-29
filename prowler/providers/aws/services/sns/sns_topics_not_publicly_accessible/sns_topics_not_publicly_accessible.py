from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.lib.policy_condition_parser.policy_condition_parser import (
    is_condition_block_restrictive,
)
from prowler.providers.aws.services.sns.sns_client import sns_client


class sns_topics_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for topic in sns_client.topics:
            report = Check_Report_AWS(self.metadata())
            report.region = topic.region
            report.resource_id = topic.name
            report.resource_arn = topic.arn
            report.resource_tags = topic.tags
            report.status = "PASS"
            report.status_extended = (
                f"SNS topic {topic.name} is not publicly accesible."
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
                            if (
                                "Condition" in statement
                                and is_condition_block_restrictive(
                                    statement["Condition"], sns_client.audited_account
                                )
                            ):
                                report.status_extended = f"SNS topic {topic.name} is not public because its policy only allows access from the same account."
                            else:
                                report.status = "FAIL"
                                report.status_extended = f"SNS topic {topic.name} is public because its policy allows public access."

            findings.append(report)

        return findings

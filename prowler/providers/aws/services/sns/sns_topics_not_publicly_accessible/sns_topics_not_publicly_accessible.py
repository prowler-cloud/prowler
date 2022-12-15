from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sns.sns_client import sns_client


class sns_topics_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for topic in sns_client.topics:
            report = Check_Report_AWS(self.metadata())
            report.region = topic.region
            report.resource_id = topic.name
            report.resource_arn = topic.arn
            report.status = "PASS"
            report.status_extended = f"SNS topic {topic.name} without public access"
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
                            if "Condition" not in statement:
                                report.status = "FAIL"
                                report.status_extended = (
                                    f"SNS topic {topic.name} policy with public access"
                                )
                            else:
                                report.status = "FAIL"
                                report.status_extended = f"SNS topic {topic.name} policy with public access but has a Condition"

            findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.lib.policy_condition_parser.policy_condition_parser import (
    is_condition_block_restrictive,
    is_condition_block_restrictive_organization,
)
from prowler.providers.aws.services.sns.sns_client import sns_client


class sns_topics_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for topic in sns_client.topics:
            # Get the organization id from the provider if it is not available in the client
            org_id = sns_client.provider.organizations_metadata.organization_id
            if org_id is None:
                sns_client.audit_config.get("organization_id", None)
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
                            condition_account = False
                            condition_org = False
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
                                and org_id is not None
                                and is_condition_block_restrictive_organization(
                                    statement["Condition"],
                                    org_id,
                                )
                            ):
                                condition_org = True

                            if condition_account and condition_org:
                                report.status_extended = f"SNS topic {topic.name} is not public because its policy only allows access from the account {sns_client.audited_account} and organization {org_id}."
                            elif condition_account:
                                report.status_extended = f"SNS topic {topic.name} is not public because its policy only allows access from the account {sns_client.audited_account}."
                            elif condition_org:
                                report.status_extended = f"SNS topic {topic.name} is not public because its policy only allows access from the organization {org_id}."
                            else:
                                report.status = "FAIL"
                                report.status_extended = f"SNS topic {topic.name} is public because its policy allows public access."
                                break

            findings.append(report)

        return findings

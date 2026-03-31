from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.iam_policy_no_wildcard_marketplace_subscribe.iam_policy_no_wildcard_marketplace_subscribe import (
    _policy_allows_marketplace_subscribe_on_all_resources,
)


class iam_inline_policy_no_wildcard_marketplace_subscribe(Check):
    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        for policy in iam_client.policies.values():
            if policy.type == "Inline":
                report = Check_Report_AWS(metadata=self.metadata(), resource=policy)
                report.region = iam_client.region
                report.resource_id = f"{policy.entity}/{policy.name}"
                report.status = "PASS"

                resource_type_str = report.resource_arn.split(":")[-1].split("/")[0]
                resource_attached = report.resource_arn.split("/")[-1]

                report.status_extended = f"Inline policy {policy.name}{' attached to ' + resource_type_str + ' ' + resource_attached if policy.attached else ''} does not allow 'aws-marketplace:Subscribe' on all resources."

                if (
                    policy.document
                    and _policy_allows_marketplace_subscribe_on_all_resources(
                        policy.document
                    )
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Inline policy {policy.name}{' attached to ' + resource_type_str + ' ' + resource_attached if policy.attached else ''} allows 'aws-marketplace:Subscribe' on all resources."

                findings.append(report)
        return findings

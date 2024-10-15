from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


class opensearch_service_domains_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for domain in opensearch_client.opensearch_domains.values():
            report = Check_Report_AWS(self.metadata())
            report.region = domain.region
            report.resource_id = domain.name
            report.resource_arn = domain.arn
            report.resource_tags = domain.tags
            report.status = "PASS"
            report.status_extended = (
                f"Opensearch domain {domain.name} is not publicly accessible."
            )

            if domain.vpc_id:
                report.status_extended = f"Opensearch domain {domain.name} is in a VPC, then it is not publicly accessible."
            elif domain.access_policy and is_policy_public(
                domain.access_policy, opensearch_client.audited_account
            ):
                report.status = "FAIL"
                report.status_extended = f"Opensearch domain {domain.name} is publicly accessible via access policy."

            findings.append(report)

        return findings

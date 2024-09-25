from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class opensearch_service_domains_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for domain in opensearch_client.opensearch_domains:
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
                public_subnets = []
                report.status_extended = f"Opensearch domain {domain.name} is in a VPC, then it is not publicly accessible."
                for subnet in domain.subnet_ids:
                    if (
                        subnet in vpc_client.vpc_subnets
                        and vpc_client.vpc_subnets[subnet].public
                    ):
                        public_subnets.append(subnet)

                if len(public_subnets) > 0:
                    report.status = "FAIL"
                    report.status_extended = f"Opensearch domain {domain.name} is publicly accessible due to public subnets: {', '.join(public_subnets)}."
            elif domain.access_policy and is_policy_public(domain.access_policy):
                report.status = "FAIL"
                report.status_extended = f"Opensearch domain {domain.name} is publicly accessible via access policy."

            findings.append(report)

        return findings

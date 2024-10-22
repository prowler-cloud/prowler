from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.opensearch.opensearch_client import opensearch_client


class opensearch_in_vpc_only(Check):
    def execute(self):
        findings = []

        for domain in opensearch_client.opensearch_domains:
            report = Check_Report_AWS(self.metadata())
            report.region = domain.region
            report.resource_id = domain.name
            report.resource_arn = domain.arn
            report.resource_tags = domain.tags

            # Check if the domain is in a VPC
            if domain.vpc_id:
                report.status = "PASS"
                report.status_extended = f"OpenSearch domain {domain.name} is within a VPC."
            else:
                report.status = "FAIL"
                report.status_extended = f"OpenSearch domain {domain.name} is not within a VPC."

            findings.append(report)

        return findings

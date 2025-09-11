from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)


class cloudfront_distributions_using_waf(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=distribution)
            if distribution.web_acl_id:
                report.status = "PASS"
                report.status_extended = f"CloudFront Distribution {distribution.id} is using AWS WAF web ACL {distribution.web_acl_id}."
            else:
                report.status = "FAIL"
                report.status_extended = f"CloudFront Distribution {distribution.id} is not using AWS WAF web ACL."
            findings.append(report)

        return findings

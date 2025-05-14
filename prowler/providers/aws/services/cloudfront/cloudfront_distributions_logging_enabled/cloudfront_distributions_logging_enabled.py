from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)


class cloudfront_distributions_logging_enabled(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=distribution)
            if distribution.logging_enabled or (
                distribution.default_cache_config
                and distribution.default_cache_config.realtime_log_config_arn
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"CloudFront Distribution {distribution.id} has logging enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"CloudFront Distribution {distribution.id} has logging disabled."
                )
            findings.append(report)

        return findings

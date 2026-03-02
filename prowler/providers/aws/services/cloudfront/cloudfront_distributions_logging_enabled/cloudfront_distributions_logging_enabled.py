from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)


class cloudfront_distributions_logging_enabled(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=distribution)
            has_legacy_logging = distribution.logging_enabled
            has_realtime_logging = (
                distribution.default_cache_config
                and distribution.default_cache_config.realtime_log_config_arn
            )
            has_v2_logging = distribution.logging_v2_enabled

            if has_legacy_logging or has_realtime_logging or has_v2_logging:
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

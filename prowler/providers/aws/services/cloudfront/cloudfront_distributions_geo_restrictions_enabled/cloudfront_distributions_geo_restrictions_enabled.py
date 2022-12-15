from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)
from prowler.providers.aws.services.cloudfront.cloudfront_service import (
    GeoRestrictionType,
)


class cloudfront_distributions_geo_restrictions_enabled(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = distribution.region
            report.resource_arn = distribution.arn
            report.resource_id = distribution.id
            if distribution.geo_restriction_type == GeoRestrictionType.none:
                report.status = "FAIL"
                report.status_extended = f"CloudFront Distribution {distribution.id} has Geo restrictions disabled"
            else:
                report.status = "PASS"
                report.status_extended = f"CloudFront Distribution {distribution.id} has Geo restrictions enabled"

            findings.append(report)

        return findings

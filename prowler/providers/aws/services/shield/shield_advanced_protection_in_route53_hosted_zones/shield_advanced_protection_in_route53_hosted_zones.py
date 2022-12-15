from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.route53.route53_client import route53_client
from prowler.providers.aws.services.shield.shield_client import shield_client


class shield_advanced_protection_in_route53_hosted_zones(Check):
    def execute(self):
        findings = []
        if shield_client.enabled:
            for hosted_zone in route53_client.hosted_zones.values():
                report = Check_Report_AWS(self.metadata())
                report.region = shield_client.region
                report.resource_id = hosted_zone.id
                report.resource_arn = hosted_zone.arn
                report.status = "FAIL"
                report.status_extended = f"Route53 Hosted Zone {hosted_zone.id} is not protected by AWS Shield Advanced"

                for protection in shield_client.protections.values():
                    if hosted_zone.arn == protection.resource_arn:
                        report.status = "PASS"
                        report.status_extended = f"Route53 Hosted Zone {hosted_zone.id} is protected by AWS Shield Advanced"
                        break

                findings.append(report)

        return findings

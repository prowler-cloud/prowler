from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.route53.route53_client import route53_client


class route53_public_hosted_zones_cloudwatch_logging_enabled(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        for hosted_zone in route53_client.hosted_zones.values():
            if not hosted_zone.private_zone:
                report = Check_Report_AWS(self.metadata())
                report.resource_id = hosted_zone.id
                report.region = hosted_zone.region
                if (
                    hosted_zone.logging_config
                    and hosted_zone.logging_config.cloudwatch_log_group_arn
                ):
                    report.status = "PASS"
                    report.status_extended = f"Route53 Public Hosted Zone {hosted_zone.id} has query logging enabled in Log Group {hosted_zone.logging_config.cloudwatch_log_group_arn}"

                else:
                    report.status = "FAIL"
                    report.status_extended = f"Route53 Public Hosted Zone {hosted_zone.id} has query logging disabled"

                findings.append(report)

        return findings

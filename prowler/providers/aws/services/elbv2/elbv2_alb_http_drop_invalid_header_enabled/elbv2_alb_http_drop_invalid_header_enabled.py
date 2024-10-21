from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client

class elbv2_alb_http_drop_invalid_header_enabled(Check):
    def execute(self):
        findings = []

        for lb in elbv2_client.loadbalancersv2.values():
            report = Check_Report_AWS(self.metadata())
            report.region = lb.region
            report.resource_id = lb.name
            report.resource_arn = lb.arn
            report.resource_tags = lb.tags
            if lb.drop_invalid_header_fields and lb.drop_invalid_header_fields == "true":
                report.status = "PASS"
                report.status_extended = f"ALB {lb.name} has 'routing.http.drop_invalid_header_fields.enabled' set to true."
            else:
                report.status = "FAIL"
                report.status_extended = f"ALB {lb.name} does not have 'routing.http.drop_invalid_header_fields.enabled' set to true."

            findings.append(report)

        return findings

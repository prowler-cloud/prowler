from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_alb_waf_enabled(Check):
    def execute(self):
        findings = []

        # Iterate through all load balancers
        for lb in elbv2_client.loadbalancersv2.values():  # Access load balancers
            report = Check_Report_AWS(self.metadata())
            report.region = lb.region
            report.resource_id = lb.name
            report.resource_arn = lb.arn
            report.resource_tags = lb.tags

            # Check if WAF is enabled for the ALB
            if lb.waf_enabled and lb.waf_enabled == "true":
                report.status = "PASS"
                report.status_extended = f"ALB {lb.name} has WAF enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"ALB {lb.name} does not have WAF enabled."

            findings.append(report)

        return findings

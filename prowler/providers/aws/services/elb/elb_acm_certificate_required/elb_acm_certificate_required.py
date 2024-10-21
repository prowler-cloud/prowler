from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elb.elb_client import elb_client
from prowler.lib.logger import logger  # Add logging

class elb_acm_certificate_required(Check):
    def execute(self):
        findings = []
        logger.info("Executing elb_acm_certificate_required check")
        
        for lb in elb_client.loadbalancers.values():
            report = Check_Report_AWS(self.metadata())
            report.region = lb.region
            report.resource_id = lb.name
            report.resource_arn = lb.arn
            report.resource_tags = lb.tags

            has_acm_certificate = self.check_acm_certificate(lb)
            if has_acm_certificate:
                report.status = "PASS"
                report.status_extended = f"Classic Load Balancer {lb.name} has an ACM certificate attached."
            else:
                report.status = "FAIL"
                report.status_extended = f"Classic Load Balancer {lb.name} does not have an ACM certificate attached."

            findings.append(report)
        
        return findings

    def check_acm_certificate(self, lb):
        # Check through listeners for HTTPS and ACM certificates
        for listener in lb.listeners:
            if listener.protocol == 'HTTPS':  # Check for HTTPS protocol
                # field for policies or SSL certificate attachment
                for policy in listener.policies:
                    if policy.startswith('arn:aws:acm:'):
                        return True
        return False

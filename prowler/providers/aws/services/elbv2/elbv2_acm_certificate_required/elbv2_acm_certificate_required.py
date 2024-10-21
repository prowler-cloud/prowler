from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client
from prowler.lib.logger import logger

class elbv2_acm_certificate_required(Check):
    def execute(self):
        findings = []
        logger.info("Executing elbv2_acm_certificate_required check")
        
        for lb in elbv2_client.loadbalancersv2.values():
            report = Check_Report_AWS(self.metadata())
            report.region = lb.region
            report.resource_id = lb.name
            report.resource_arn = lb.arn
            report.resource_tags = lb.tags

            has_acm_certificate = self.check_acm_certificate(lb)
            if has_acm_certificate:
                report.status = "PASS"
                report.status_extended = f"ALB load balancer {lb.name} has an ACM certificate attached."
            else:
                report.status = "FAIL"
                report.status_extended = f"ALB load balancer {lb.name} does not have an ACM certificate attached."

            findings.append(report)
        
        return findings

    def check_acm_certificate(self, lb):
        for listener in lb.listeners.values():
            if listener.protocol == 'HTTPS':
                for cert in listener.certificates:
                    if cert.get('CertificateArn', '').startswith('arn:aws:acm:'):
                        return True
        return False

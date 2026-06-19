from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.loadbalancer.loadbalancer_client import (
    loadbalancer_client,
)


class loadbalancer_alb_https_uses_ssl_certificate(Check):
    def execute(self):
        findings = []
        for lb in loadbalancer_client.load_balancers:
            if not lb.is_alb_https:
                continue

            report = CheckReportE2e(metadata=self.metadata(), resource=lb)
            report.status = "PASS"
            report.status_extended = (
                f"Load balancer {lb.name} uses an SSL certificate for HTTPS traffic."
            )
            if not lb.ssl_certificate_id:
                report.status = "FAIL"
                report.status_extended = (
                    f"Load balancer {lb.name} does not have an SSL certificate configured for HTTPS traffic."
                )
            findings.append(report)
        return findings

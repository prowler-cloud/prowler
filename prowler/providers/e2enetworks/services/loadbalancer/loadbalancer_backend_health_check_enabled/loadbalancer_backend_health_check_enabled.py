from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_client import (
    loadbalancer_client,
)


class loadbalancer_backend_health_check_enabled(Check):
    """Check that ALB load balancers have backend health checks configured."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for lb in loadbalancer_client.load_balancers:
            if not lb.is_alb:
                continue

            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=lb)
            report.status = "PASS"
            report.status_extended = (
                f"Load balancer {lb.name} has backend health checks configured."
            )
            if not lb.has_backend_health_check:
                report.status = "FAIL"
                report.status_extended = f"Load balancer {lb.name} does not have backend health checks configured."
            findings.append(report)
        return findings

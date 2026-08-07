from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_client import (
    loadbalancer_client,
)


class loadbalancer_bitninja_enabled(Check):
    """Check that load balancers have BitNinja protection enabled."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for lb in loadbalancer_client.load_balancers:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=lb)
            report.status = "PASS"
            report.status_extended = (
                f"Load balancer {lb.name} has BitNinja protection enabled."
            )
            if not lb.enable_bitninja:
                report.status = "FAIL"
                report.status_extended = f"Load balancer {lb.name} does not have BitNinja protection enabled."
            findings.append(report)
        return findings

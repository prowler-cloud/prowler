from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.database.database_client import (
    database_client,
)


class database_cluster_ip_whitelist_configured(Check):
    """Check if E2E Networks database clusters with public IPs have IP whitelisting configured."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for cluster in database_client.clusters:
            if not cluster.master_has_public_ip:
                continue
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=cluster)
            report.status = "PASS"
            report.status_extended = (
                f"Database cluster {cluster.name} has IP whitelisting configured."
            )
            if not cluster.whitelisted_ips:
                report.status = "FAIL"
                report.status_extended = f"Database cluster {cluster.name} has a public IP but no whitelisted IPs."
            findings.append(report)
        return findings

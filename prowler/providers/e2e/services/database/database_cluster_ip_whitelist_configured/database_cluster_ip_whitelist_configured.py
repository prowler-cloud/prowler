from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.database.database_client import database_client


class database_cluster_ip_whitelist_configured(Check):
    def execute(self):
        findings = []
        for cluster in database_client.clusters:
            if not cluster.master_has_public_ip:
                continue
            report = CheckReportE2e(metadata=self.metadata(), resource=cluster)
            report.status = "PASS"
            report.status_extended = (
                f"Database cluster {cluster.name} has IP whitelisting configured."
            )
            if not cluster.whitelisted_ips:
                report.status = "FAIL"
                report.status_extended = (
                    f"Database cluster {cluster.name} has a public IP but no whitelisted IPs."
                )
            findings.append(report)
        return findings

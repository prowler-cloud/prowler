from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.database.database_client import database_client


class database_cluster_default_admin_username(Check):
    def execute(self):
        findings = []
        for cluster in database_client.clusters:
            report = CheckReportE2e(metadata=self.metadata(), resource=cluster)
            report.status = "PASS"
            report.status_extended = (
                f"Database cluster {cluster.name} does not use the default admin username."
            )
            if cluster.master_username.lower() == "admin":
                report.status = "FAIL"
                report.status_extended = (
                    f"Database cluster {cluster.name} uses the default admin username."
                )
            findings.append(report)
        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.redshift.redshift_client import redshift_client


class redshift_cluster_non_default_username(Check):
    def execute(self):
        findings = []
        for cluster in redshift_client.clusters:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=cluster
            )
            report.status = "PASS"
            report.status_extended = f"Redshift Cluster {cluster.id} does not have the default Admin username."
            if cluster.master_username == "awsuser":
                report.status = "FAIL"
                report.status_extended = (
                    f"Redshift Cluster {cluster.id} has the default Admin username."
                )

            findings.append(report)

        return findings

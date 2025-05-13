from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.redshift.redshift_client import redshift_client


class redshift_cluster_encrypted_at_rest(Check):
    def execute(self):
        findings = []
        for cluster in redshift_client.clusters:
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            report.status = "FAIL"
            report.status_extended = (
                f"Redshift Cluster {cluster.id} is not encrypted at rest."
            )
            if cluster.encrypted:
                report.status = "PASS"
                report.status_extended = (
                    f"Redshift Cluster {cluster.id} is encrypted at rest."
                )

            findings.append(report)

        return findings

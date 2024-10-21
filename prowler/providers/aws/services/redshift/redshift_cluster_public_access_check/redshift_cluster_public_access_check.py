from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.redshift.redshift_client import redshift_client

class redshift_cluster_public_access_check(Check):
    def execute(self):
        findings = []

        # Iterate through Redshift clusters
        for cluster in redshift_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags

            # Check if public access is enabled
            if cluster.public_access:
                report.status = "FAIL"
                report.status_extended = f"Redshift cluster {cluster.id} has public access enabled."
            else:
                report.status = "PASS"
                report.status_extended = f"Redshift cluster {cluster.id} does not have public access enabled."

            findings.append(report)

        return findings

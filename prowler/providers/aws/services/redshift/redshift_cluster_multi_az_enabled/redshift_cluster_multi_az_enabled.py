from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.redshift.redshift_client import redshift_client


class redshift_cluster_multi_az_enabled(Check):
    def execute(self):
        findings = []
        for cluster in redshift_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags
            report.status = "FAIL"
            report.status_extended = (
                f"Redshift Cluster {cluster.id} does not have Multi-AZ enabled."
            )
            if cluster.multi_az:
                report.status = "PASS"
                report.status_extended = (
                    f"Redshift Cluster {cluster.id} has Multi-AZ enabled."
                )

            findings.append(report)

        return findings

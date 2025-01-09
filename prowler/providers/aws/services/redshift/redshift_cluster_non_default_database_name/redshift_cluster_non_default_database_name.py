from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.redshift.redshift_client import redshift_client


class redshift_cluster_non_default_database_name(Check):
    def execute(self):
        findings = []
        for cluster in redshift_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags
            report.status = "PASS"
            report.status_extended = f"Redshift Cluster {cluster.id} does not have the default database name."
            if cluster.database_name == "dev":
                report.status = "FAIL"
                report.status_extended = f"Redshift Cluster {cluster.id} has the default database name: {cluster.database_name}."

            findings.append(report)

        return findings

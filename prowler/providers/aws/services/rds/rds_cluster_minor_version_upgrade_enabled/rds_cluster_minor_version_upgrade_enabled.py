from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_cluster_minor_version_upgrade_enabled(Check):
    def execute(self):
        findings = []
        for db_cluster in rds_client.db_clusters:
            # Auto minor version upgrade is only available for non-Aurora Multi-AZ DB clusters
            if rds_client.db_clusters[db_cluster].multi_az:
                report = Check_Report_AWS(self.metadata())
                report.region = rds_client.db_clusters[db_cluster].region
                report.resource_id = rds_client.db_clusters[db_cluster].id
                report.resource_arn = rds_client.db_clusters[db_cluster].arn
                report.resource_tags = rds_client.db_clusters[db_cluster].tags
                if rds_client.db_clusters[db_cluster].auto_minor_version_upgrade:
                    report.status = "PASS"
                    report.status_extended = f"RDS Cluster {rds_client.db_clusters[db_cluster].id} has minor version upgrade enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"RDS Cluster {rds_client.db_clusters[db_cluster].id} does not have minor version upgrade enabled."

                findings.append(report)

        return findings

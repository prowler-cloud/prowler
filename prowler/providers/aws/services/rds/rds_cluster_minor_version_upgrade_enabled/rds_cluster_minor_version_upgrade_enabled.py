from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_cluster_minor_version_upgrade_enabled(Check):
    def execute(self):
        findings = []
        for db_cluster in rds_client.db_clusters:
            if db_cluster.multi_az:
                report = Check_Report_AWS(self.metadata())
                report.region = db_cluster.region
                report.resource_id = db_cluster.id
                report.resource_arn = db_cluster.arn
                report.resource_tags = db_cluster.tags
                if db_cluster.auto_minor_version_upgrade:
                    report.status = "PASS"
                    report.status_extended = f"RDS Cluster {db_cluster.id} has minor version upgrade enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"RDS Cluster {db_cluster.id} does not have minor version upgrade enabled."

                findings.append(report)

        return findings

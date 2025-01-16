from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_cluster_storage_encrypted(Check):
    def execute(self):
        findings = []
        for db_cluster in rds_client.db_clusters.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=db_cluster
            )
            if db_cluster.encrypted:
                report.status = "PASS"
                report.status_extended = f"RDS cluster {db_cluster.id} is encrypted."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS cluster {db_cluster.id} is not encrypted."
                )

            findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.documentdb.documentdb_client import (
    documentdb_client,
)


class documentdb_cluster_storage_encrypted(Check):
    def execute(self):
        findings = []
        for db_cluster in documentdb_client.db_clusters.values():
            report = Check_Report_AWS(self.metadata())
            report.region = db_cluster.region
            report.resource_id = db_cluster.id
            report.resource_arn = db_cluster.arn
            report.resource_tags = db_cluster.tags
            if db_cluster.encrypted:
                report.status = "PASS"
                report.status_extended = (
                    f"DocumentDB Cluster {db_cluster.id} is encrypted at rest."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"DocumentDB Cluster {db_cluster.id} is not encrypted at rest."
                )

            findings.append(report)

        return findings

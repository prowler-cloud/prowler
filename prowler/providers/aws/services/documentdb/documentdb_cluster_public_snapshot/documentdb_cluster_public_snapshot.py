from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.documentdb.documentdb_client import (
    documentdb_client,
)


class documentdb_cluster_public_snapshot(Check):
    def execute(self):
        findings = []
        for db_snap in documentdb_client.db_cluster_snapshots:
            report = Check_Report_AWS(self.metadata())
            report.region = db_snap.region
            report.resource_id = db_snap.id
            report.resource_arn = db_snap.arn
            report.resource_tags = db_snap.tags
            if db_snap.public:
                report.status = "FAIL"
                report.status_extended = (
                    f"DocumentDB Cluster Snapshot {db_snap.id} is public."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"DocumentDB Cluster Snapshot {db_snap.id} is not shared publicly."
                )

            findings.append(report)

        return findings

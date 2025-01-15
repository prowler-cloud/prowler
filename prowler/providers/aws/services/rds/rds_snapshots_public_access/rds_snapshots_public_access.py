from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_snapshots_public_access(Check):
    def execute(self):
        findings = []
        for db_snap in rds_client.db_snapshots:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=db_snap
            )
            if db_snap.public:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS Instance Snapshot {db_snap.id} is public."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS Instance Snapshot {db_snap.id} is not shared."
                )

            findings.append(report)

        for db_snap in rds_client.db_cluster_snapshots:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=db_snap
            )
            if db_snap.public:
                report.status = "FAIL"
                report.status_extended = f"RDS Cluster Snapshot {db_snap.id} is public."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS Cluster Snapshot {db_snap.id} is not shared."
                )

            findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_snapshots_public_prohibited(Check):
    def execute(self):
        findings = []

        # Iterate over all RDS snapshots
        for snapshot in rds_client.db_snapshots:
            report = Check_Report_AWS(self.metadata())
            report.region = snapshot.region
            report.resource_id = snapshot.id
            report.resource_arn = snapshot.arn
            report.resource_tags = snapshot.tags

            # Check if the snapshot is publicly accessible
            if snapshot.public:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS snapshot {snapshot.id} is publicly accessible."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS snapshot {snapshot.id} is not publicly accessible."
                )

            # Append the report to the findings list
            findings.append(report)

        return findings

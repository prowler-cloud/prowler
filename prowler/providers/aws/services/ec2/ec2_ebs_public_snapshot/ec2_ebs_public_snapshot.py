from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ebs_public_snapshot(Check):
    def execute(self):
        reports = []
        for snapshot in ec2_client.iter_snapshots(determine_public=True):
            report = Check_Report_AWS(metadata=self.metadata(), resource=snapshot)
            report.status = "PASS"
            report.status_extended = f"EBS Snapshot {snapshot.id} is not Public."
            if snapshot.public:
                report.status = "FAIL"
                report.status_extended = (
                    f"EBS Snapshot {snapshot.id} is currently Public."
                )
            reports.append(report)
        return reports

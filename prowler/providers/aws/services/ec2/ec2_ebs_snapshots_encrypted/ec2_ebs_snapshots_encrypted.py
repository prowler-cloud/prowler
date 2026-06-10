from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ebs_snapshots_encrypted(Check):
    def execute(self):
        def evaluate(snapshot):
            report = Check_Report_AWS(metadata=self.metadata(), resource=snapshot)
            report.status = "PASS"
            report.status_extended = f"EBS Snapshot {snapshot.id} is encrypted."
            if not snapshot.encrypted:
                report.status = "FAIL"
                report.status_extended = f"EBS Snapshot {snapshot.id} is unencrypted."
            return report

        reports = []
        for resource in ec2_client.iter_snapshots():
            report = evaluate(resource)
            if report is not None:
                reports.append(report)
        return reports

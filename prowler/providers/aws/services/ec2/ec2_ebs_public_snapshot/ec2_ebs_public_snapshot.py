from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ebs_public_snapshot(Check):
    def execute(self):
        findings = []
        for snapshot in ec2_client.snapshots:
            report = Check_Report_AWS(self.metadata())
            report.region = snapshot.region
            report.resource_arn = snapshot.arn
            if not snapshot.public:
                report.status = "PASS"
                report.status_extended = f"EBS Snapshot {snapshot.id} is not Public."
                report.resource_id = snapshot.id
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"EBS Snapshot {snapshot.id} is currently Public."
                )
                report.resource_id = snapshot.id
            findings.append(report)

        return findings

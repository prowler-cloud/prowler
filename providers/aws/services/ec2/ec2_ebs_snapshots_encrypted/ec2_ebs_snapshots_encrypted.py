from lib.check.models import Check, Check_Report
from providers.aws.services.ec2.ec2_service import ec2_client


class ec2_ebs_snapshots_encrypted(Check):
    def execute(self):
        findings = []
        for regional_client in ec2_client.regional_clients:
            region = regional_client.region
            if hasattr(regional_client, "snapshots"):
                if regional_client.snapshots:
                    for snapshot in regional_client.snapshots:
                        report = Check_Report(self.metadata)
                        report.region = region
                        if snapshot["Encrypted"]:
                            report.status = "PASS"
                            report.status_extended = (
                                f"EBS Snapshot {snapshot['SnapshotId']} is encrypted"
                            )
                            report.resource_id = snapshot["SnapshotId"]
                        else:
                            report.status = "FAIL"
                            report.status_extended = (
                                f"EBS Snapshot {snapshot['SnapshotId']} is unencrypted"
                            )
                            report.resource_id = snapshot["SnapshotId"]
                else:
                    report = Check_Report(self.metadata)
                    report.status = "PASS"
                    report.status_extended = "There are no EC2 EBS snapshots"
                    report.region = region

                findings.append(report)

        return findings

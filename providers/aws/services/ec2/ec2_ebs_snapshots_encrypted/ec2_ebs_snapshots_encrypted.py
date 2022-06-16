from datetime import datetime

from lib.check import Check, Check_Report
from providers.aws.services.ec2.ec2_service import ec2_client


class ec2_ebs_snapshots_encrypted(Check):
    def execute(self):
        findings = []
        for regional_client in ec2_client.regional_clients:
            region = regional_client.region
            if regional_client.snapshots:
                if 'error' in regional_client.snapshots:
                        report = Check_Report()
                        report.status = "ERROR"
                        report.result_extended = f"{regional_client.snapshots}"
                        report.region = region
                else:
                    for snapshot in regional_client.snapshots:
                        if snapshot["Encrypted"]:
                            report = Check_Report()
                            report.status = "PASS"
                            report.result_extended = f"EBS Snapshot {snapshot['SnapshotId']} is encrypted"
                            report.region = region
                        else:
                            report = Check_Report()
                            report.status = "FAIL"
                            report.result_extended = f"EBS Snapshot {snapshot['SnapshotId']} is unencrypted"
                            report.region = region
            else:
                report = Check_Report()
                report.status = "PASS"
                report.result_extended = "There are no EC2 EBS snapshots"
                report.region = region

            findings.append(report)

        return findings

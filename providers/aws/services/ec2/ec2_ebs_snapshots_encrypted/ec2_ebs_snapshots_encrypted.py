from datetime import datetime

from lib.check import Check, Check_Report
from providers.aws.services.ec2.ec2_service import ec2_client


class ec2_ebs_snapshots_encrypted(Check):
    def execute(self):
        findings = []
        for result in ec2_client.snapshots:
            report = Check_Report()
            response = result['response']
            if response:
                if 'error' in response:
                        report.status = "ERROR"
                        report.result_extended = f"{response}"
                        report.region = result['region']
                else:
                    for snapshot in response:
                        if snapshot["Encrypted"]:
                            report.status = "PASS"
                            report.result_extended = f"EBS Snapshot {snapshot['SnapshotId']} is encrypted"
                            report.region = result['region']
                        else:
                            report.status = "FAIL"
                            report.result_extended = f"EBS Snapshot {snapshot['SnapshotId']} is unencrypted"
                            report.region = result['region']
            else:
                report.status = "PASS"
                report.result_extended = "There are no EC2 EBS snapshots"
                report.region = result['region']

            findings.append(report)

        return findings

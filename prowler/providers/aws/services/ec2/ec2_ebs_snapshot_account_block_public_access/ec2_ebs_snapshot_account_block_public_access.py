from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ebs_snapshot_account_block_public_access(Check):
    def execute(self):
        findings = []
        for (
            ebs_snapshot_block_status
        ) in ec2_client.ebs_block_public_access_snapshots_states:
            if (
                ebs_snapshot_block_status.snapshots
                or ec2_client.provider.scan_unused_services
            ):
                report = Check_Report_AWS(self.metadata())
                report.region = ebs_snapshot_block_status.region
                report.resource_arn = ec2_client.account_arn_template
                report.resource_id = ec2_client.audited_account
                if ebs_snapshot_block_status.status == "block-all-sharing":
                    report.status = "PASS"
                    report.status_extended = (
                        "Public access is blocked for all EBS Snapshots."
                    )
                elif ebs_snapshot_block_status.status == "block-new-sharing":
                    report.status = "FAIL"
                    report.status_extended = (
                        "Public access is blocked only for new EBS Snapshots."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        "Public access is not blocked for EBS Snapshots."
                    )
                findings.append(report)

        return findings

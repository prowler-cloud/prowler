from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ebs_block_public_access_snapshots(Check):
    def execute(self):
        findings = []
        for (
            ebs_snapchot_block_status
        ) in ec2_client.ebs_block_public_access_snapshots_state:
            if (
                ebs_snapchot_block_status.snapshots
                or ec2_client.provider.scan_unused_services
            ):
                report = Check_Report_AWS(self.metadata())
                report.region = ebs_snapchot_block_status.region
                report.resource_arn = f"arn:aws:ec2:{ebs_snapchot_block_status.region}:{ec2_client.audited_account}"
                report.resource_id = ec2_client.audited_account
                if ebs_snapchot_block_status.status == "block-all-sharing":
                    report.status = "PASS"
                    report.status_extended = f"EBS Snapshots for region {ebs_snapchot_block_status.region} public access is blocked."
                elif ebs_snapchot_block_status.status == "block-new-sharing":
                    report.status = "FAIL"
                    report.status_extended = f"EBS Snapshots for region {ebs_snapchot_block_status.region} public access is not blocked for new snapshots."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"EBS Snapshots for region {ebs_snapchot_block_status.region} public access is not blocked."
                findings.append(report)

        return findings

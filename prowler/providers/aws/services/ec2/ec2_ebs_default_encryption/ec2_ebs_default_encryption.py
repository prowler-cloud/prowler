from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ebs_default_encryption(Check):
    def execute(self):
        findings = []
        for ebs_encryption in ec2_client.ebs_encryption_by_default:
            if ebs_encryption.volumes or ec2_client.provider.scan_unused_services:
                report = Check_Report_AWS(self.metadata())
                report.region = ebs_encryption.region
                report.resource_arn = ec2_client.__get_volume_arn_template__(
                    ebs_encryption.region
                )
                report.resource_id = ec2_client.audited_account
                report.status = "FAIL"
                report.status_extended = "EBS Default Encryption is not activated."
                if ebs_encryption.status:
                    report.status = "PASS"
                    report.status_extended = "EBS Default Encryption is activated."
                findings.append(report)

        return findings

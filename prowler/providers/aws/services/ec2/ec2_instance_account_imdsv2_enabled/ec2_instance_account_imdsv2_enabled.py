from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_account_imdsv2_enabled(Check):
    def execute(self):
        findings = []
        for instance_metadata_default in ec2_client.instance_metadata_defaults:
            if (
                instance_metadata_default.instances
                or ec2_client.provider.scan_unused_services
            ):
                report = Check_Report_AWS(self.metadata())
                report.region = instance_metadata_default.region
                report.resource_arn = ec2_client.account_arn_template
                report.resource_id = ec2_client.audited_account
                if instance_metadata_default.http_tokens == "required":
                    report.status = "PASS"
                    report.status_extended = (
                        "IMDSv2 is enabled by default for EC2 instances."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        "IMDSv2 is not enabled by default for EC2 instances."
                    )
                findings.append(report)

        return findings

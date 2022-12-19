from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ami_public(Check):
    def execute(self):
        findings = []
        for image in ec2_client.images:
            report = Check_Report_AWS(self.metadata())
            report.region = image.region
            report.resource_id = image.id
            report.status = "PASS"
            report.status_extended = f"EC2 AMI {image.id} is not public."
            if image.public:
                report.status = "FAIL"
                report.status_extended = f"EC2 AMI {image.id} is currently public."
                report.resource_id = image.id

            findings.append(report)

        return findings

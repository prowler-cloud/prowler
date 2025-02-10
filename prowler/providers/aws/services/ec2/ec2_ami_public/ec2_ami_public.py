from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ami_public(Check):
    def execute(self):
        findings = []
        for image in ec2_client.images:
            report = Check_Report_AWS(metadata=self.metadata(), resource=image)
            report.status = "PASS"
            report.status_extended = (
                f"EC2 AMI {image.name if image.name else image.id} is not public."
            )
            if image.public:
                report.status = "FAIL"
                report.status_extended = f"EC2 AMI {image.name if image.name else image.id} is currently public."

            findings.append(report)

        return findings

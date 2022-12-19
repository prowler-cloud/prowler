from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_internet_facing_with_instance_profile(Check):
    def execute(self):
        findings = []
        for instance in ec2_client.instances:
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_id = instance.id
            report.status = "PASS"
            report.status_extended = f"EC2 Instance {instance.id} is not internet facing with an instance profile."
            if instance.public_ip and instance.instance_profile:
                report.status = "FAIL"
                report.status_extended = f"EC2 Instance {instance.id} at IP {instance.public_ip} is internet-facing with Instance Profile {instance.instance_profile['Arn']}."

            findings.append(report)

        return findings

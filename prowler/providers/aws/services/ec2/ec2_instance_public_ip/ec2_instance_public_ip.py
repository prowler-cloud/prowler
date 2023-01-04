from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_public_ip(Check):
    def execute(self):
        findings = []
        for instance in ec2_client.instances:
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_arn = instance.arn
            if instance.public_ip:
                report.status = "FAIL"
                report.status_extended = f"EC2 Instance {instance.id} has a Public IP: {instance.public_ip} ({instance.public_dns})."
                report.resource_id = instance.id
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"EC2 Instance {instance.id} has not a Public IP."
                )
                report.resource_id = instance.id
            findings.append(report)

        return findings

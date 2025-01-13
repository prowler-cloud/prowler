from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_public_ip(Check):
    def execute(self):
        findings = []
        for instance in ec2_client.instances:
            if instance.state != "terminated":
                report = Check_Report_AWS(self.metadata(), instance)
                report.status = "PASS"
                report.status_extended = (
                    f"EC2 Instance {instance.id} does not have a Public IP."
                )
                if instance.public_ip:
                    report.status = "FAIL"
                    report.status_extended = f"EC2 Instance {instance.id} has a Public IP: {instance.public_ip} ({instance.public_dns})."

                findings.append(report)

        return findings

from lib.check.models import Check, Check_Report
from providers.aws.services.ec2.ec2_service import ec2_client


class ec2_instance_public_ip(Check):
    def execute(self):
        findings = []
        for regional_client in ec2_client.regional_clients:
            region = regional_client.region
            if regional_client.instances:
                for instance in regional_client.instances:
                    report = Check_Report(self.metadata)
                    report.region = region
                    if instance.public_ip:
                        report.status = "FAIL"
                        report.status_extended = f"EC2 instance {instance.id} has a Public IP: {instance.public_ip} ({instance.public_dns})."
                        report.resource_id = instance.id
                    else:
                        report.status = "PASS"
                        report.status_extended = (
                            f"EC2 instance {instance.id} has not a Public IP."
                        )
                        report.resource_id = instance.id
                    findings.append(report)
            else:
                report = Check_Report(self.metadata)
                report.status = "PASS"
                report.status_extended = "There are no EC2 instances."
                report.region = region

                findings.append(report)

        return findings

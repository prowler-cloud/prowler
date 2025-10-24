from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ecs.ecs_client import ecs_client

class ecs_instance_public_ip(Check):
    def execute(self):
        findings = []
        for instance_arn, instance in ecs_client.instances.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=instance)
            report.account_uid = ecs_client.account_id
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = instance.arn
            
            if not instance.public_ip:
                report.status = "PASS"
                report.status_extended = f"ECS instance {instance.name} does not have a public IP address."
            else:
                report.status = "FAIL"
                report.status_extended = f"ECS instance {instance.name} has public IP {instance.public_ip}. Consider using EIP or NAT Gateway instead."
            findings.append(report)
        return findings

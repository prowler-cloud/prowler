from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ecs.ecs_client import ecs_client


class ecs_instance_public_ip(Check):
    def execute(self):
        findings = []
        for instance in ecs_client.instances.values():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=instance
            )
            report.status = "FAIL"
            report.status_extended = (
                f"ECS instance {instance.name} has public IP {instance.public_ip}."
            )
            if not instance.public_ip:
                report.status = "PASS"
                report.status_extended = (
                    f"ECS instance {instance.name} does not have a public IP address."
                )
            findings.append(report)
        return findings

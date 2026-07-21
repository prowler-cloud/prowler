from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.ecs.ecs_client import ecs_client


class ecs_instance_public_ip(Check):
    """Ensure ECS instances do not have public IP addresses."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for instance in ecs_client.instances.values():
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=instance)
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = f"huaweicloud:ecs:{instance.region}:{ecs_client.audited_account}:instance/{instance.id}"

            if instance.public_ip:
                report.status = "FAIL"
                report.status_extended = f"ECS instance {instance.name} ({instance.id}) has a public IP: {instance.public_ip}."
            else:
                report.status = "PASS"
                report.status_extended = f"ECS instance {instance.name} ({instance.id}) does not have a public IP."

            findings.append(report)

        return findings

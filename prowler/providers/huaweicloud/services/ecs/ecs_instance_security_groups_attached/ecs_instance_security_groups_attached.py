from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.ecs.ecs_client import ecs_client


class ecs_instance_security_groups_attached(Check):
    """Ensure ECS instances have security groups attached."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for instance in ecs_client.instances.values():
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=instance)
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = f"huaweicloud:ecs:{instance.region}:{ecs_client.audited_account}:instance/{instance.id}"

            if instance.security_groups:
                sg_names = ", ".join(
                    name or sg_id for sg_id, name in instance.security_groups.items()
                )
                report.status = "PASS"
                report.status_extended = f"ECS instance {instance.name} ({instance.id}) has security group(s) attached: {sg_names}."
            else:
                report.status = "FAIL"
                report.status_extended = f"ECS instance {instance.name} ({instance.id}) does not have any security groups attached."

            findings.append(report)

        return findings

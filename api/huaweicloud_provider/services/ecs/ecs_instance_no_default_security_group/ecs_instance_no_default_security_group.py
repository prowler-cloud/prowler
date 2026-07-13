from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.ecs.ecs_client import ecs_client


class ecs_instance_no_default_security_group(Check):
    """Ensure ECS instances do not use the default security group."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for instance in ecs_client.instances.values():
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=instance)
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = (
                f"huaweicloud:ecs:{instance.region}:{ecs_client.audited_account}:instance/{instance.id}"
            )

            default_sgs = [
                sg_id
                for sg_id, sg_name in instance.security_groups.items()
                if sg_name == "default" or sg_id == "default"
            ]

            if default_sgs:
                report.status = "FAIL"
                report.status_extended = (
                    f"ECS instance {instance.name} ({instance.id}) uses the default security group: {', '.join(default_sgs)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"ECS instance {instance.name} ({instance.id}) does not use the default security group."
                )

            findings.append(report)

        return findings

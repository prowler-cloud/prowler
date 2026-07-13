from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.ecs.ecs_client import ecs_client


class ecs_instance_key_pair(Check):
    """Ensure ECS instances use SSH key pairs for authentication."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for instance in ecs_client.instances.values():
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=instance)
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = (
                f"huaweicloud:ecs:{instance.region}:{ecs_client.audited_account}:instance/{instance.id}"
            )

            if instance.key_name:
                report.status = "PASS"
                report.status_extended = (
                    f"ECS instance {instance.name} ({instance.id}) uses SSH key pair '{instance.key_name}' for authentication."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"ECS instance {instance.name} ({instance.id}) does not use an SSH key pair for authentication."
                )

            findings.append(report)

        return findings

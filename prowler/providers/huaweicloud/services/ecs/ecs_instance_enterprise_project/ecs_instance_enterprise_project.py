from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.ecs.ecs_client import ecs_client


class ecs_instance_enterprise_project(Check):
    """Ensure ECS instances are assigned to an enterprise project."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for instance in ecs_client.instances.values():
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=instance)
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = f"huaweicloud:ecs:{instance.region}:{ecs_client.audited_account}:instance/{instance.id}"

            if instance.enterprise_project_id:
                report.status = "PASS"
                report.status_extended = f"ECS instance {instance.name} ({instance.id}) is assigned to enterprise project '{instance.enterprise_project_id}'."
            else:
                report.status = "FAIL"
                report.status_extended = f"ECS instance {instance.name} ({instance.id}) is not assigned to an enterprise project."

            findings.append(report)

        return findings

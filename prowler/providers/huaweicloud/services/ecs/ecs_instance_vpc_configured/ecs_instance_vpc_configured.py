from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.ecs.ecs_client import ecs_client


class ecs_instance_vpc_configured(Check):
    """Ensure ECS instances are deployed within a VPC."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for instance in ecs_client.instances.values():
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=instance)
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = (
                f"huaweicloud:ecs:{instance.region}:"
                f"{ecs_client.audited_account}:instance/{instance.id}"
            )

            if instance.vpc_id:
                report.status = "PASS"
                report.status_extended = (
                    f"ECS instance {instance.name} ({instance.id}) "
                    f"is deployed within VPC '{instance.vpc_id}'."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"ECS instance {instance.name} ({instance.id}) "
                    f"is not deployed within a VPC."
                )

            findings.append(report)

        return findings

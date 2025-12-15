from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ecs.ecs_client import ecs_client


class ecs_instance_no_legacy_network(Check):
    """Check if ECS instances are not using legacy (classic) network."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for instance in ecs_client.instances:
            report = CheckReportAlibabaCloud(
                metadata=self.metadata(), resource=instance
            )
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = f"acs:ecs:{instance.region}:{ecs_client.audited_account}:instance/{instance.id}"

            if instance.network_type == "classic":
                report.status = "FAIL"
                report.status_extended = (
                    f"ECS instance {instance.name if instance.name else instance.id} "
                    f"is using legacy (classic) network type."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"ECS instance {instance.name if instance.name else instance.id} "
                    f"is using VPC network type."
                )

            findings.append(report)

        return findings

from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ecs.ecs_client import ecs_client
from prowler.providers.alibabacloud.services.securitycenter.securitycenter_client import (
    securitycenter_client,
)


class ecs_instance_endpoint_protection_installed(Check):
    """Check if endpoint protection for all Virtual Machines is installed."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        # Check each ECS instance for Security Center agent
        for instance in ecs_client.instances:
            # Only check running instances
            if instance.status.lower() not in ["running", "starting"]:
                continue

            report = CheckReportAlibabaCloud(
                metadata=self.metadata(), resource=instance
            )
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = f"acs:ecs:{instance.region}:{ecs_client.audited_account}:instance/{instance.id}"

            # Check if Security Center agent is installed
            instance_key = f"{instance.region}:{instance.id}"
            agent = securitycenter_client.instance_agents.get(instance_key)

            if agent:
                if agent.agent_installed and agent.agent_status == "online":
                    report.status = "PASS"
                    report.status_extended = (
                        f"ECS instance {instance.name if instance.name else instance.id} "
                        "has Security Center agent installed and online."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"ECS instance {instance.name if instance.name else instance.id} "
                        f"does not have Security Center agent installed or agent is {agent.agent_status}."
                    )

                findings.append(report)

        return findings
